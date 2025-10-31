package job

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/clamav"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
	"github.com/accuknox/omniscan/pkg/scanner/winvuln"
)

type RunConfig struct {
	Logger                     *slog.Logger
	VulnScan                   bool
	VulnScanDBDir              string
	UseEmbeddedTrivy           bool
	MalwareScan                bool
	MalwareScanTargetDirectory string
	UseClamAVDaemon            bool
	OfflineWinVulnScan         bool
}

type Run struct {
	RunConfig
}

type RunResult struct {
	OS                  string
	MalwareScanFindings scanner.Findings
	VulnScanFindings    scanner.Findings
	MalwareScanError    error
	VulnScanError       error
}

func NewRun(c RunConfig) Run {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return Run{RunConfig: c}
}

func (r Run) ScanMountPoint(ctx context.Context, os, mount, vmURI, platform string) (*RunResult, error) {
	if r.MalwareScanTargetDirectory == "" {
		r.MalwareScanTargetDirectory = mount
	}

	result := RunResult{OS: os}

	// clamAV supports both windows and linux
	if r.MalwareScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running malware scan",
			slog.String("target_directory", r.MalwareScanTargetDirectory),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		result.MalwareScanFindings, result.MalwareScanError = clamav.
			NewScanner(r.UseClamAVDaemon).
			Scan(
				ctx,
				r.MalwareScanTargetDirectory,
				vmURI,
				platform,
				os,
			)
	}

	// windows vuln scan
	if os == "windows" && r.VulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running windows vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		opts := []winvuln.OptFunc{
			winvuln.WithDBPath(filepath.Join(r.VulnScanDBDir, "msrc", "msrc.sqlite")),
		}
		if r.OfflineWinVulnScan {
			opts = append(opts, winvuln.WithUseOfflineMode())
		}
		result.VulnScanFindings, result.VulnScanError = winvuln.NewScanner(opts...).Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		return &result, nil
	}

	// linux vuln scan
	if r.VulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)
		opts := []trivy.OptFunc{trivy.WithUseEmbeddedTrivy(r.UseEmbeddedTrivy)}
		if r.VulnScanDBDir != "" {
			opts = append(opts, trivy.WithCacheDirectory(r.VulnScanDBDir))
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
