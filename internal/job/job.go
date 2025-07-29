package job

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/scanner/clamscan"
	"github.com/accuknox/omniscan/internal/scanner/trivy"
	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/resource"

	"github.com/go-co-op/gocron/v2"
	"github.com/jaypipes/ghw"
)

type Job struct {
	p              provider.Provider
	opts           opts
	artifactConfig artifact.Config
}

type ErrorSummary struct {
	OS             string
	ExecutionError error
	ClamscanError  error
	TrivyError     error
}

func NewScanJob(p provider.Provider, c artifact.Config, optFns ...OptFunc) (*Job, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating provided artifact API config: %w", err)
	}
	o := defaultOpts()
	for _, fn := range optFns {
		fn(&o)
	}
	return &Job{
		p:              p,
		opts:           o,
		artifactConfig: c,
	}, nil
}

func (j Job) Run(ctx context.Context) (map[string]ErrorSummary, error) {
	if err := os.MkdirAll(j.opts.mountpoint, 0o755); err != nil {
		return nil, fmt.Errorf(
			"creating mount directory %q: %w",
			j.opts.mountpoint, err,
		)
	}

	if err := j.p.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialization given provider: %w", err)
	}

	host, err := j.p.GetCurrentVM(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching current VM: %w", err)
	}

	vms, err := j.p.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing all VMs: %w", err)
	}

	result := make(map[string]ErrorSummary)

	for _, target := range vms {
		var summary ErrorSummary

		res, err := j.scanVM(ctx, *host, target)
		if res == nil && err == nil {
			continue
		}
		if err != nil {
			summary.ExecutionError = err
		}
		if res != nil {
			summary.OS = res.OS
			summary.ClamscanError = res.ClamscanError
			summary.TrivyError = res.TrivyError
			err := j.publish(ctx, res)
			if err != nil {
				summary.ExecutionError = fmt.Errorf("publishing artifact: %w", err)
			}
		}

		result[target.URI] = summary
	}

	return result, nil
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

func (j Job) scanVM(ctx context.Context, host, target resource.VM) (*execResult, error) {
	if len(target.Disks) == 0 {
		slog.LogAttrs(
			ctx,
			slog.LevelInfo,
			"no disks attached to vm. Skipping...",
			slog.String("vm_uri", target.URI),
		)
		return nil, nil
	}
	disk := target.Disks[0] // first disk is always the boot disk

	clone, err := j.createDiskClone(ctx, disk.URI)
	if err != nil {
		return nil, err
	}
	defer j.p.DeleteDisk(ctx, clone)

	slog.LogAttrs(
		ctx,
		slog.LevelDebug,
		"succesfully cloned disk",
		slog.String("cloned_disk_uri", clone),
	)

	err = j.mountClonedDisk(ctx, clone, host.URI)
	if err != nil {
		return nil, err
	}
	defer j.p.UnmountDisk(ctx, clone, host.URI)

	slog.LogAttrs(
		ctx,
		slog.LevelDebug,
		"mounted cloned disk to host",
		slog.String("cloned_disk_uri", clone),
		slog.String("mount_point", j.opts.mountpoint),
	)

	return j.scanMountedDisk(ctx, clone, target.URI)
}

func (j Job) createDiskClone(ctx context.Context, diskURI string) (string, error) {
	snap, err := j.p.CreateSnapshot(ctx, diskURI)
	if err != nil {
		return "", fmt.Errorf("creating snapshot of disk %q: %w", diskURI, err)
	}
	defer j.p.DeleteSnapshot(ctx, snap)

	err = j.p.WaitSnapshotReady(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("waiting for snapshot %q: %w", snap, err)
	}

	clone, err := j.p.ConvertSnapshot2Disk(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("converting snapshot %q to disk: %w", snap, err)
	}

	err = j.p.WaitDiskReady(ctx, clone)
	if err != nil {
		j.p.DeleteDisk(ctx, clone)
		return "", fmt.Errorf("waiting for cloned disk %q: %w", clone, err)
	}

	return clone, nil
}

func (j Job) mountClonedDisk(ctx context.Context, diskURI, hostURI string) error {
	err := j.p.MountDisk(ctx, diskURI, hostURI, resource.DevicePathMagicString)
	if err != nil {
		return fmt.Errorf("mounting disk %q to host: %w", diskURI, err)
	}
	return nil
}

func (j Job) scanMountedDisk(ctx context.Context, diskURI, targetURI string) (*execResult, error) {
	parts, err := util.ListUnmountedPartitions(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing unmounted partitions: %w", err)
	}

	for _, p := range parts {
		slog.LogAttrs(
			ctx,
			slog.LevelDebug,
			"attempting to scan disk partition",
			slog.String("cloned_disk_uri", diskURI),
			slog.String("partition", p.Name),
		)

		result, err := j.scanPartition(ctx, p, targetURI)
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

func (j Job) scanPartition(ctx context.Context, p ghw.Partition, targetURI string) (*execResult, error) {
	if p.Disk.SerialNumber != resource.DevicePathMagicString {
		slog.LogAttrs(
			ctx,
			slog.LevelDebug,
			"partition doesn not contain magic string. Skipping...",
			slog.String("partition", p.Name),
			slog.String("magic_string", resource.DevicePathMagicString),
			slog.String("disk_name", p.Name),
		)
		return nil, nil
	}
	if p.Type == "unknown" {
		slog.LogAttrs(
			ctx,
			slog.LevelInfo,
			"partition filesystem unknown. Skipping...",
			slog.String("partition", p.Name),
			slog.String("disk_name", p.Disk.Name),
		)
		return nil, nil
	}

	dev := "/dev/" + p.Name
	err := j.mountPartition(ctx, dev, p.Type)
	if err != nil {
		return nil, err
	}
	defer util.Unmount(ctx, j.opts.mountpoint)

	slog.LogAttrs(
		ctx,
		slog.LevelDebug,
		"mounted partition to host",
		slog.String("partition", p.Name),
	)

	osType := j.detectOS()
	if osType == "unknown" {
		slog.LogAttrs(
			ctx,
			slog.LevelDebug,
			"could not determine OS. Skipping...",
			slog.String("partition", p.Name),
		)
		return nil, nil
	}
	slog.LogAttrs(
		ctx,
		slog.LevelDebug,
		"OS detected",
		slog.String("partition", p.Name),
		slog.String("os", osType),
	)

	return j.performScans(ctx, osType, targetURI)
}

func (j Job) mountPartition(ctx context.Context, dev, fsType string) error {
	err := util.MountRO(ctx, dev, j.opts.mountpoint, fsType)
	if err != nil {
		return fmt.Errorf(
			"mounting partition %q to %q: %w",
			dev, j.opts.mountpoint, err,
		)
	}
	return nil
}

func (j Job) detectOS() string {
	linuxProb := util.DetectLinuxRootFS(j.opts.mountpoint)
	winProb := util.DetectWindowsRootFS(j.opts.mountpoint)
	if linuxProb < .5 && winProb < .5 {
		return "unknown"
	}
	if linuxProb > winProb {
		return "linux"
	}
	return "windows"
}

func (j Job) performScans(ctx context.Context, osType, targetURI string) (*execResult, error) {
	f := execResult{OS: osType}
	platform := j.p.GetName()

	if j.opts.clamscanEnabled {
		f.Clamscan, f.ClamscanError = clamscan.Scan(
			ctx,
			j.opts.mountpoint,
			targetURI,
			platform,
		)
		slog.LogAttrs(
			ctx,
			slog.LevelDebug,
			"clamav scan completed",
			slog.String("os", osType),
			slog.String("mount_point", j.opts.mountpoint),
			slog.String("target_uri", targetURI),
			slog.String("platform", platform),
		)
	}

	if osType == "windows" {
		return &f, nil
	}

	if j.opts.trivyEnabled {
		f.Trivy, f.TrivyError = trivy.Scan(
			ctx,
			j.opts.mountpoint,
			targetURI,
			platform,
		)
		slog.LogAttrs(
			ctx,
			slog.LevelDebug,
			"trivy scan completed",
			slog.String("os", osType),
			slog.String("mount_point", j.opts.mountpoint),
			slog.String("target_uri", targetURI),
			slog.String("platform", platform),
		)
	}

	return &f, nil
}

func (j Job) publish(ctx context.Context, raw *execResult) error {
	var items []artifact.Findings
	if raw.ClamscanError == nil && raw.Clamscan != nil {
		items = append(items, raw.Clamscan)
	}
	if raw.TrivyError == nil && raw.Trivy != nil {
		items = append(items, raw.Trivy)
	}
	if len(items) == 0 {
		return nil
	}

	pub, err := artifact.NewPublisher(j.artifactConfig)
	if err != nil {
		return fmt.Errorf("creating artifact publisher: %w", err)
	}

	return pub.Publish(ctx, items)
}
