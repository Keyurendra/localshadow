package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/go-co-op/gocron/v2"

	"github.com/accuknox/omniscan/pkg/job"
	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/util"
)

type Job struct {
	opts
	pub publisher.Publisher
}

func NewJob(pub publisher.Publisher, optFns ...OptFunc) (*Job, error) {
	o := defaultOpts()
	for _, fn := range optFns {
		fn(&o)
	}
	return &Job{
		opts: o,
		pub:  pub,
	}, nil
}

func (j Job) Schedule(ctx context.Context, crontab string, triggerNow bool) error {
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
	if triggerNow {
		opts = append(opts, gocron.WithStartAt(gocron.WithStartImmediately()))
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"creating scan job",
		slog.String("crontab", crontab),
		slog.Bool("trigger_now", triggerNow),
	)
	_, err = s.NewJob(
		gocron.CronJob(crontab, false),
		gocron.NewTask(j.Run, ctx),
		opts...,
	)
	if err != nil {
		return fmt.Errorf("creating scheduled job: %w", err)
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

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

func (j Job) Run(ctx context.Context, mountpoint string) (job.ErrorSummaryMap, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("get system hostname: %w", err)
	}
	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"queried system information",
		slog.String("hostname", hostname),
	)

	result, err := j.scanMountPoint(ctx, mountpoint, hostname)
	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"scan complete",
		slog.String("mountpoint", mountpoint),
	)

	var errors job.ErrorSummary

	if err != nil {
		errors.OrchestrationError = err
	}

	if result != nil {
		errors.OS = result.OS
		if result.MalwareScanError != nil {
			errors.MalwareScanError = result.MalwareScanError
		}
		if result.VulnScanError != nil {
			errors.VulnScanError = result.VulnScanError
		}
		err := result.Publish(ctx, j.pub)
		if err != nil {
			errors.ArtifactAPIError = fmt.Errorf("publishing artifact: %w", err)
		}
	}

	return job.ErrorSummaryMap{hostname: errors}, nil
}

func (j Job) scanMountPoint(ctx context.Context, mountpoint, vmURI string) (*job.RunResult, error) {
	osType := util.DetectOS(mountpoint)
	if osType == "unknown" {
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"could not determine the OS on mounted partition. Skipping...",
			slog.String("partition_name", mountpoint),
		)
		return nil, nil
	}
	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"OS detected on mounted partition",
		slog.String("partition_name", mountpoint),
		slog.String("os", osType),
	)
	run := job.NewRun(
		j.vulnScanEnabled,
		j.malwareScanEnabled,
		false,
		true,
		j.vulnDBDirectory,
		j.logger,
	)
	return run.ScanMountPoint(ctx, osType, mountpoint, vmURI, "agent")
}
