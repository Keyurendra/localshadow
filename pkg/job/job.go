package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/accuknox/omniscan/pkg/metric"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/publisher/cspm"
	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/clamav"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/util"

	"github.com/go-co-op/gocron/v2"
	"github.com/jaypipes/ghw"
)

type Job struct {
	opts
	prov       provider.Provider
	pub        publisher.Publisher
	cspmConfig cspm.Config
	collector  *metric.Collector
}

func NewScanJob(prov provider.Provider, pub publisher.Publisher, optFns ...OptFunc) (*Job, error) {
	o := defaultOpts()
	for _, fn := range optFns {
		fn(&o)
	}
	var (
		collector *metric.Collector
		err       error
	)
	if o.prometheusMetrics {
		collector, err = metric.NewCollector(o.prometheusMetricsPort)
		if err != nil {
			return nil, fmt.Errorf("creating metrics collector: %w", err)
		}
	}
	return &Job{
		opts:      o,
		prov:      prov,
		pub:       pub,
		collector: collector,
	}, nil
}

func (j Job) Run(ctx context.Context) (map[string]ErrorSummary, error) {
	j.logger.LogAttrs(ctx, slog.LevelInfo, "initializing provider")
	if err := j.prov.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialization given provider: %w", err)
	}

	j.logger.LogAttrs(ctx, slog.LevelInfo, "pruning dangling resources")
	if err := j.pruneDangling(ctx); err != nil {
		return nil, fmt.Errorf("cleaning dangling resources: %w", err)
	}

	j.logger.LogAttrs(ctx, slog.LevelInfo, "querying host info from provider")
	host, err := j.prov.GetCurrentVM(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching current VM: %w", err)
	}

	j.logger.LogAttrs(ctx, slog.LevelInfo, "querying VM list from provider")
	vms, err := j.prov.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing all VMs: %w", err)
	}

	queue := newQueue(j.concurrency)

	for _, target := range vms {
		j.logger.LogAttrs(
			ctx,
			slog.LevelDebug,
			"blocking until scan is enqueued to the concurrent task queue",
			slog.String("target_vm_uri", target.URI),
		)
		err = queue.Enqueue(ctx, func() (string, *ErrorSummary) {
			j.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"starting scan",
				slog.String("target_vm_uri", target.URI),
			)

			res, err := j.scanVM(ctx, *host, target)

			j.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"scan completed",
				slog.String("target_vm_uri", target.URI),
			)

			if res == nil && err == nil {
				return target.URI, nil
			}

			var errors ErrorSummary

			if err != nil {
				errors.OrchestrationError = err
			}

			if res != nil {
				errors.OS = res.OS
				errors.ClamscanError = res.ClamscanError
				errors.TrivyError = res.TrivyError
				j.logger.LogAttrs(
					ctx,
					slog.LevelInfo,
					"publishing scan results",
					slog.String("target_vm_uri", target.URI),
				)
				err := j.publish(ctx, res)
				if err != nil {
					errors.ArtifactAPIError = fmt.Errorf(
						"publishing artifact: %w",
						err,
					)
				}
			}

			if anyNonNil(errors.OrchestrationError, errors.TrivyError, errors.ClamscanError) {
				j.logger.LogAttrs(
					ctx,
					slog.LevelError,
					"errors encountered during scan",
					slog.String("target_vm_uri", target.URI),
					slog.Group(
						"errors",
						slog.Any("orchestration", errors.OrchestrationError),
						slog.Any("trivy", errors.TrivyError),
						slog.Any("clamav", errors.ClamscanError),
					),
				)
			}

			if !j.prometheusMetrics {
				return target.URI, &errors
			}

			osTyp := metric.OSTypeUnknown
			if res != nil {
				switch res.OS {
				case "windows":
					osTyp = metric.OSTypeWindows
				case "linux":
					osTyp = metric.OSTypeLinux
				}
			}

			if errors.OrchestrationError != nil {
				j.collector.RecordError(metric.ErrorTypeOrchestration, osTyp)
			}

			if errors.TrivyError != nil {
				j.collector.RecordError(metric.ErrorTypeVulnScan, osTyp)
			}

			if errors.ClamscanError != nil {
				j.collector.RecordError(metric.ErrorTypeMalwareScan, osTyp)
			}

			if errors.ArtifactAPIError != nil {
				j.collector.RecordError(metric.ErrorTypeArtifactAPI, osTyp)
			}

			if errors.ArtifactAPIError == nil && errors.TrivyError == nil {
				j.collector.RecordSuccessfulScan(metric.ScanTypeVulnScan, osTyp)
			}

			if errors.ArtifactAPIError == nil && errors.ClamscanError == nil {
				j.collector.RecordSuccessfulScan(metric.ScanTypeMalwareScan, osTyp)
			}

			return target.URI, &errors
		})
		if err != nil {
			break
		}
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"all scans queued, awaiting completion",
	)

	return queue.Wait(), err
}

func (j Job) Schedule(ctx context.Context, c ScheduleConfig) error {
	j.logger.LogAttrs(ctx, slog.LevelInfo, "creating scheduler")
	s, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("creating scheduler: %w", err)
	}

	opts := []gocron.JobOption{
		gocron.WithContext(ctx),
		gocron.WithSingletonMode(gocron.LimitModeWait),
		gocron.WithName("scan"),
	}
	if c.TriggerJobImmediately {
		opts = append(opts, gocron.WithStartAt(gocron.WithStartImmediately()))
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"creating scan job",
		slog.String("crontab", c.Crontab),
		slog.Bool("trigger_immediately", c.TriggerJobImmediately),
	)
	_, err = s.NewJob(
		gocron.CronJob(c.Crontab, false),
		gocron.NewTask(j.Run, ctx),
		opts...,
	)
	if err != nil {
		return fmt.Errorf("creating scheduled job: %w", err)
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if !j.prometheusMetrics {
			return
		}
		defer cancel()
		err := j.collector.ServeHTTP(ctx)
		if err != nil {
			j.logger.LogAttrs(
				ctx,
				slog.LevelError,
				"prometheus metric endpoint terminated",
				slog.Any("error", err),
			)
		}
	}()

	s.Start() // non-blocking

	<-ctx.Done() // interrupt/sigterm received

	j.logger.LogAttrs(ctx, slog.LevelInfo, "waiting for metric server to stop")
	wg.Wait()

	j.logger.LogAttrs(ctx, slog.LevelInfo, "shutting down scheduler")
	if err := s.Shutdown(); err != nil {
		return err
	}

	return nil
}

func (j Job) pruneDangling(ctx context.Context) error {
	entries, err := os.ReadDir(j.baseMountPoint)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"listing directories at mountpoint %s: %w",
			j.baseMountPoint, err,
		)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(j.baseMountPoint, entry.Name())
		if err := util.Unmount(ctx, path); err != nil {
			j.logger.LogAttrs(
				ctx,
				slog.LevelWarn,
				"unmounting dangling partition",
				slog.String("mount_point", path),
				slog.Any("error", err),
			)
		}
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
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"no disks attached to the target VM. Skipping...",
			slog.String("target_vm_uri", target.URI),
		)
		return nil, nil
	}
	disk := target.Disks[0] // first disk is always the boot disk

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"cloning disk",
		slog.String("disk_uri", disk.URI),
		slog.String("source_vm_uri", target.URI),
	)
	clone, err := j.createDiskClone(ctx, disk.URI)
	if err != nil {
		return nil, err
	}
	defer j.prov.DeleteDisk(ctx, clone)

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"mounting cloned disk to host",
		slog.String("cloned_disk_uri", clone),
		slog.String("source_disk_uri", disk.URI),
		slog.String("host_vm_uri", host.URI),
	)
	defer j.prov.DetachDisk(ctx, clone, host.URI)
	path, err := j.attachClonedDisk(ctx, clone, host.URI)
	if err != nil {
		return nil, err
	}

	return j.scanAttachedDisk(ctx, path, clone, target.URI)
}

func (j Job) createDiskClone(ctx context.Context, diskURI string) (string, error) {
	j.logger.LogAttrs(
		ctx,
		slog.LevelDebug,
		"creating snapshot of source disk",
		slog.String("source_disk_uri", diskURI),
	)
	snap, err := j.prov.CreateSnapshot(ctx, diskURI)
	if err != nil {
		return "", fmt.Errorf("creating snapshot of disk %q: %w", diskURI, err)
	}
	defer j.prov.DeleteSnapshot(ctx, snap)

	j.logger.LogAttrs(
		ctx,
		slog.LevelDebug,
		"waiting for snapshot to be ready",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", diskURI),
	)
	err = j.prov.WaitSnapshotReady(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("waiting for snapshot %q: %w", snap, err)
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelDebug,
		"creating disk from the snapshot",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", diskURI),
	)
	clone, err := j.prov.ConvertSnapshot2Disk(ctx, snap)
	if err != nil {
		return "", fmt.Errorf("converting snapshot %q to disk: %w", snap, err)
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelDebug,
		"waiting for cloned disk to be ready",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", diskURI),
		slog.String("cloned_disk_uri", clone),
	)
	err = j.prov.WaitDiskReady(ctx, clone)
	if err != nil {
		j.prov.DeleteDisk(ctx, clone)
		return "", fmt.Errorf("waiting for cloned disk %q: %w", clone, err)
	}

	return clone, nil
}

func (j Job) attachClonedDisk(ctx context.Context, diskURI, hostURI string) (string, error) {
	path, err := j.prov.AttachDisk(ctx, diskURI, hostURI)
	if err != nil {
		return "", fmt.Errorf("mounting disk %q to host: %w", diskURI, err)
	}
	return path, nil
}

func (j Job) scanAttachedDisk(ctx context.Context, path, diskURI, targetVMURI string) (*execResult, error) {
	parts, err := util.ListUnmountedPartitions(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing unmounted partitions: %w", err)
	}

	for _, p := range parts {
		if p.Disk.Name != strings.TrimPrefix(path, "/dev/") {
			continue
		}
		j.logger.LogAttrs(
			ctx,
			slog.LevelDebug,
			"attempting to scan partition",
			slog.String("partition_name", p.Name),
			slog.String("cloned_disk_uri", diskURI),
			slog.String("target_vm_uri", targetVMURI),
		)
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
	if p.Type == "unknown" {
		j.logger.LogAttrs(
			ctx,
			slog.LevelDebug,
			"partition fs type is unknown. Skipping...",
			slog.String("cloned_disk_uri", diskURI),
			slog.String("target_vm_uri", targetVMURI),
			slog.String("partition_name", p.Name),
		)
		return nil, nil
	}

	dev := "/dev/" + p.Name
	mountPoint, err := j.mountPartition(ctx, dev, p.Type)
	if err != nil {
		return nil, err
	}
	defer util.Unmount(ctx, mountPoint)

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"partition mounted for scanning",
		slog.String("cloned_disk_uri", diskURI),
		slog.String("target_vm_uri", targetVMURI),
		slog.String("partition_name", p.Name),
		slog.String("mount_point", mountPoint),
	)

	osType := j.detectOS(mountPoint)
	if osType == "unknown" {
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"could not determine the OS on mounted partition. Skipping...",
			slog.String("cloned_disk_uri", diskURI),
			slog.String("target_vm_uri", targetVMURI),
			slog.String("partition_name", p.Name),
		)
		return nil, nil
	}
	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"OS detected on mounted partition",
		slog.String("cloned_disk_uri", diskURI),
		slog.String("target_vm_uri", targetVMURI),
		slog.String("partition_name", p.Name),
		slog.String("os", osType),
	)

	return j.performScans(ctx, mountPoint, osType, targetVMURI)
}

func (j Job) mountPartition(ctx context.Context, dev, fsType string) (string, error) {
	at, err := util.MountRO(ctx, dev, j.baseMountPoint, fsType)
	if err != nil {
		return "", fmt.Errorf(
			"mounting partition %q to %q: %w",
			dev, j.baseMountPoint, err,
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

	if j.clamscanEnabled {
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running clamav scan",
			slog.String("mount_point", mountPoint),
			slog.String("os", osType),
			slog.String("target_vm_uri", targetURI),
		)
		f.Clamscan, f.ClamscanError = clamav.NewScanner().Scan(
			ctx,
			mountPoint,
			targetURI,
			platform,
			osType,
		)
	}

	if osType == "windows" {
		j.logger.LogAttrs(
			ctx,
			slog.LevelDebug,
			"trivy scan is not supported for windows. Skipping...",
			slog.String("mount_point", mountPoint),
			slog.String("os", osType),
			slog.String("target_vm_uri", targetURI),
		)
		return &f, nil
	}

	if j.trivyEnabled {
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running trivy scan",
			slog.String("mount_point", mountPoint),
			slog.String(`os`, osType),
			slog.String("target_vm_uri", targetURI),
		)
		f.Trivy, f.TrivyError = trivy.NewScanner().Scan(
			ctx,
			mountPoint,
			targetURI,
			platform,
			osType,
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

func anyNonNil(args ...any) bool {
	for _, arg := range args {
		if arg != nil {
			return true
		}
	}
	return false
}
