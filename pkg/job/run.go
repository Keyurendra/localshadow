package job

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/clamav"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
)

type Run struct {
	logger           *slog.Logger
	vulnScan         bool
	vulnScanDBDir    string
	useEmbeddedTrivy bool
	malwareScan      bool
	useClamAVDaemon  bool
}

type RunResult struct {
	OS                  string
	MalwareScanFindings scanner.Findings
	VulnScanFindings    scanner.Findings
	MalwareScanError    error
	VulnScanError       error
}

func NewRun(vulnScan, malwareScan, useClamAVDaemon, useEmbeddedTrivy bool, vulnScanDBDir string, logger *slog.Logger) Run {
	if logger == nil {
		logger = slog.Default()
	}
	return Run{
		vulnScan:         vulnScan,
		malwareScan:      malwareScan,
		useClamAVDaemon:  useClamAVDaemon,
		useEmbeddedTrivy: useEmbeddedTrivy,
		vulnScanDBDir:    vulnScanDBDir,
		logger:           logger,
	}
}

func (r Run) ScanMountPoint(ctx context.Context, os, mount, vmURI, platform string) (*RunResult, error) {
	result := RunResult{OS: os}

	if r.malwareScan {
		r.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running malware scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		result.MalwareScanFindings, result.MalwareScanError = clamav.
			NewScanner(r.useClamAVDaemon).
			Scan(
				ctx,
				mount,
				vmURI,
				platform,
				os,
			)
	}

	if os == "windows" {
		r.logger.LogAttrs(
			ctx,
			slog.LevelDebug,
			"trivy scan is not supported for windows. Skipping...",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		return &result, nil
	}

	if r.vulnScan {
		r.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		opts := []trivy.OptFunc{trivy.WithUseEmbeddedTrivy(r.useEmbeddedTrivy)}
		if r.vulnScanDBDir != "" {
			opts = append(opts, trivy.WithCacheDirectory(r.vulnScanDBDir))
		}
		trivyScanner, err := trivy.NewScanner(opts...)
		if err != nil {
			return nil, fmt.Errorf("initializing vuln scanner: %w", err)
		}
		result.VulnScanFindings, result.VulnScanError = trivyScanner.Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
	}

	return &result, nil
}

func (r RunResult) Publish(ctx context.Context, pub publisher.Publisher) error {
	var items []scanner.Findings
	if r.MalwareScanError == nil && r.MalwareScanFindings != nil {
		items = append(items, r.MalwareScanFindings)
	}
	if r.VulnScanError == nil && r.VulnScanFindings != nil {
		items = append(items, r.VulnScanFindings)
	}
	if len(items) == 0 {
		return nil
	}
	return pub.Publish(ctx, items...)
}
