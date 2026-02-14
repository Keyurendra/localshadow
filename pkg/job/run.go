package job

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/clamav"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/container"
	"github.com/accuknox/omniscan/pkg/scanner/trivy/rootfs"
	"github.com/accuknox/omniscan/pkg/scanner/winvuln"
)

type RunConfig struct {
	Logger                           *slog.Logger
	VulnScan                         bool
	VulnScanDBDir                    string
	CRISockets                       []string
	ContainerImageScanRemoteFallback bool
	UseEmbeddedTrivy                 bool
	MalwareScan                      bool
	MalwareScanTargetDirectory       string
	UseClamAVDaemon                  bool
	DaemonlessClamavDBDir            string
	OfflineWinVulnScan               bool
	ContainerVulnScan                bool
}

type Run struct {
	RunConfig
}

type RunResult struct {
	OS                     string
	MalwareScanError       error
	VulnScanError          error
	ContainerVulnScanError error
	ArtifactPublishError   error
}

func NewRun(c RunConfig) Run {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return Run{RunConfig: c}
}

func (r Run) ScanMountPoint(ctx context.Context, os, mount, vmURI, platform string, pub scanner.Publish) (*RunResult, error) {
	if r.MalwareScanTargetDirectory == "" {
		r.MalwareScanTargetDirectory = mount
	}

	result := RunResult{OS: os}
	trackedPub := func(ctx context.Context, f scanner.Findings) error {
		if f == nil {
			return nil
		}
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"publishing findings",
			slog.String("data_type", f.DataType()),
			slog.String("target_vm_uri", vmURI),
			slog.String("os", os),
		)
		if err := pub(ctx, f); err != nil {
			result.ArtifactPublishError = errors.Join(result.ArtifactPublishError, err)
			return err
		}
		return nil
	}

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

		finding, err := clamav.
			NewScanner(r.UseClamAVDaemon, r.DaemonlessClamavDBDir).
			Scan(
				ctx,
				r.MalwareScanTargetDirectory,
				vmURI,
				platform,
				os,
			)
		result.MalwareScanError = err
		if err == nil && finding != nil {
			trackedPub(ctx, finding)
		}
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
			winvuln.WithDBPath(filepath.Join(r.VulnScanDBDir, "msrc", "db.sqlite3")),
		}
		if r.OfflineWinVulnScan {
			opts = append(opts, winvuln.WithUseOfflineMode())
		}

		finding, err := winvuln.NewScanner(opts...).Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		result.VulnScanError = err
		if err == nil && finding != nil {
			trackedPub(ctx, finding)
		}
		return &result, nil
	}

	if os == "linux" && r.ContainerVulnScan {
		r.Logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"running container vuln scan",
			slog.String("mount_point", mount),
			slog.String("os", os),
			slog.String("target_vm_uri", vmURI),
		)

		var opts []container.OptFunc

		if r.VulnScanDBDir != "" {
			opts = append(opts, container.WithCacheDirectory(r.VulnScanDBDir))
		}
		if len(r.CRISockets) > 0 {
			opts = append(opts, container.WithCRISockets(r.CRISockets...))
		}
		if r.ContainerImageScanRemoteFallback {
			opts = append(opts, container.WithRemoteFallback())
		}

		s, err := container.NewScanner(opts...)
		if err != nil {
			return nil, fmt.Errorf("initializing container vuln scanner: %w", err)
		}

		result.ContainerVulnScanError = s.Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
			trackedPub,
		)
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

		opts := []rootfs.OptFunc{rootfs.WithUseEmbeddedTrivy(r.UseEmbeddedTrivy)}
		if r.VulnScanDBDir != "" {
			opts = append(opts, rootfs.WithCacheDirectory(r.VulnScanDBDir))
		}

		s, err := rootfs.NewScanner(opts...)
		if err != nil {
			return nil, fmt.Errorf("initializing vuln scanner: %w", err)
		}

		finding, err := s.Scan(
			ctx,
			mount,
			vmURI,
			platform,
			os,
		)
		result.VulnScanError = err
		if err == nil && finding != nil {
			trackedPub(ctx, finding)
		}
	}

	return &result, nil
}
