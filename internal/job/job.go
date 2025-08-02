package job

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/scanner/clamav"
	"github.com/accuknox/omniscan/internal/scanner/trivy"
	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/scanner"

	"github.com/go-co-op/gocron/v2"
	"github.com/jaypipes/ghw"
)

type Job struct {
	prov           provider.Provider
	pub            publisher.Publisher
	opts           opts
	artifactConfig artifact.CSPMPublisherConfig
}

func NewScanJob(prov provider.Provider, pub publisher.Publisher, optFns ...OptFunc) Job {
	o := defaultOpts()
	for _, fn := range optFns {
		fn(&o)
	}
	return Job{
		prov: prov,
		pub:  pub,
		opts: o,
	}
}

func (j Job) Run(ctx context.Context) (map[string]ErrorSummary, error) {
	if err := j.prov.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialization given provider: %w", err)
	}

	if err := j.pruneDangling(ctx); err != nil {
		return nil, fmt.Errorf("cleaning dangling resources: %w", err)
	}

	host, err := j.prov.GetCurrentVM(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching current VM: %w", err)
	}

	vms, err := j.prov.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing all VMs: %w", err)
	}

	queue := newQueue(j.opts.concurrency)

	for _, target := range vms {
		err = queue.Enqueue(ctx, func() (string, *ErrorSummary) {
			var errors ErrorSummary

			res, err := j.scanVM(ctx, *host, target)
			if res == nil && err == nil {
				return target.URI, nil
			}

			if err != nil {
				errors.ExecutionError = err
			}

			if res != nil {
				errors.OS = res.OS
				errors.ClamscanError = res.ClamscanError
				errors.TrivyError = res.TrivyError
				err := j.publish(ctx, res)
				if err != nil {
					errors.ExecutionError = fmt.Errorf(
						"publishing artifact: %w",
						err,
					)
				}
			}

			return target.URI, &errors
		})
		if err != nil {
			break
		}
	}

	return queue.Wait(), err
}

func (j Job) Schedule(ctx context.Context, crontab string, runImmediately bool) error {
	s, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("creating scheduler: %w", err)
	}

	opts := []gocron.JobOption{
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeWait),
		gocron.WithName("scan"),
	}
	if runImmediately {
		opts = append(opts, gocron.WithStartAt(gocron.WithStartImmediately()))
	}

	_, err = s.NewJob(
		gocron.CronJob(crontab, false),
		gocron.NewTask(j.Run, ctx),
		opts...,
	)
	if err != nil {
		return fmt.Errorf("creating scheduled job: %w", err)
	}

	s.Start() // non-blocking

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done() // interrupt/sigterm received

	return s.Shutdown()
}

func (j Job) pruneDangling(ctx context.Context) error {
	entries, err := os.ReadDir(j.opts.baseMountPoint)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"listing directories at mountpoint %q: %w",
			j.opts.baseMountPoint, err,
		)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(j.opts.baseMountPoint, entry.Name())
		util.Unmount(ctx, path)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("removing dangling directory %q: %w", path, err)
		}
	}

	if err := j.prov.PruneDangling(ctx); err != nil {
		return nil
	}

	return nil
}

func (j Job) scanVM(ctx context.Context, host, target resource.VM) (*execResult, error) {
	if len(target.Disks) == 0 {
		return nil, nil
	}
	disk := target.Disks[0] // first disk is always the boot disk

	clone, err := j.createDiskClone(ctx, disk.URI)
	if err != nil {
		return nil, err
	}
	defer j.prov.DeleteDisk(ctx, clone)

	err = j.mountClonedDisk(ctx, clone, host.URI)
	if err != nil {
		return nil, err
	}
	defer j.prov.UnmountDisk(ctx, clone, host.URI)

	return j.scanMountedDisk(ctx, clone, target.URI)
}

func (j Job) createDiskClone(ctx context.Context, diskURI string) (string, error) {
	snap, err := j.prov.CreateSnapshot(ctx, diskURI)
	if err != nil {
		return "", fmt.Errorf("creating snapshot of disk %q: %w", diskURI, err)
	}
	defer j.prov.DeleteSnapshot(ctx, snap)

	err = j.prov.WaitSnapshotReady(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("waiting for snapshot %q: %w", snap, err)
	}

	clone, err := j.prov.ConvertSnapshot2Disk(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("converting snapshot %q to disk: %w", snap, err)
	}

	err = j.prov.WaitDiskReady(ctx, clone)
	if err != nil {
		j.prov.DeleteDisk(ctx, clone)
		return "", fmt.Errorf("waiting for cloned disk %q: %w", clone, err)
	}

	return clone, nil
}

func (j Job) mountClonedDisk(ctx context.Context, diskURI, hostURI string) error {
	err := j.prov.MountDisk(ctx, diskURI, hostURI, util.Sha256Hash(diskURI))
	if err != nil {
		return fmt.Errorf("mounting disk %q to host: %w", diskURI, err)
	}
	return nil
}

func (j Job) scanMountedDisk(ctx context.Context, diskURI, targetVMURI string) (*execResult, error) {
	parts, err := util.ListUnmountedPartitions(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing unmounted partitions: %w", err)
	}

	for _, p := range parts {
		result, err := j.scanPartition(ctx, p, diskURI, targetVMURI)
		if err != nil {
			return nil, fmt.Errorf(
				"scanning partition %q on disk %q: %w",
				p.Name, diskURI, err,
			)
		}
		if result != nil {
			return result, nil
		}
	}

	return nil, nil
}

func (j Job) scanPartition(ctx context.Context, p ghw.Partition, diskURI, targetVMURI string) (*execResult, error) {
	if p.Disk.SerialNumber != util.Sha256Hash(diskURI) {
		return nil, nil
	}
	if p.Type == "unknown" {
		return nil, nil
	}

	dev := "/dev/" + p.Name
	mountPoint, err := j.mountPartition(ctx, dev, p.Type)
	if err != nil {
		return nil, err
	}
	defer util.Unmount(ctx, mountPoint)

	osType := j.detectOS(mountPoint)
	if osType == "unknown" {
		return nil, nil
	}

	return j.performScans(ctx, mountPoint, osType, targetVMURI)
}

func (j Job) mountPartition(ctx context.Context, dev, fsType string) (string, error) {
	at, err := util.MountRO(ctx, dev, j.opts.baseMountPoint, fsType)
	if err != nil {
		return "", fmt.Errorf(
			"mounting partition %q to %q: %w",
			dev, j.opts.baseMountPoint, err,
		)
	}
	return at, nil
}

func (j Job) detectOS(mountPoint string) string {
	linuxProb := util.DetectLinuxRootFS(mountPoint)
	winProb := util.DetectWindowsRootFS(mountPoint)
	if linuxProb < .5 && winProb < .5 {
		return "unknown"
	}
	if linuxProb > winProb {
		return "linux"
	}
	return "windows"
}

func (j Job) performScans(ctx context.Context, mountPoint, osType, targetURI string) (*execResult, error) {
	f := execResult{OS: osType}
	platform := j.prov.GetName()

	if j.opts.clamscanEnabled {
		f.Clamscan, f.ClamscanError = clamav.NewScanner().Scan(
			ctx,
			mountPoint,
			targetURI,
			platform,
		)
	}

	if osType == "windows" {
		return &f, nil
	}

	if j.opts.trivyEnabled {
		f.Trivy, f.TrivyError = trivy.NewScanner().Scan(
			ctx,
			mountPoint,
			targetURI,
			platform,
		)
	}

	return &f, nil
}

func (j Job) publish(ctx context.Context, raw *execResult) error {
	var items []scanner.Findings
	if raw.ClamscanError == nil && raw.Clamscan != nil {
		items = append(items, raw.Clamscan)
	}
	if raw.TrivyError == nil && raw.Trivy != nil {
		items = append(items, raw.Trivy)
	}
	if len(items) == 0 {
		return nil
	}
	return j.pub.Publish(ctx, items...)
}
