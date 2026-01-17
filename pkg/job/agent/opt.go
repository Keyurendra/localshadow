package agent

import (
	"context"
	"log/slog"

	"github.com/accuknox/omniscan/pkg/util"
)

type OptFunc func(*opts)

type opts struct {
	vulnDBDirectory            string
	vulnScanEnabled            bool
	malwareScanEnabled         bool
	clamavDBDirectory          string
	malwareScanTargetDirectory string
	overrideHostname           string
	logger                     *slog.Logger
}

func WithMalwareScanDisabled() OptFunc {
	return func(o *opts) {
		o.malwareScanEnabled = false
	}
}

func WithVulnScanDisabled() OptFunc {
	return func(o *opts) {
		o.vulnScanEnabled = false
	}
}

func WithVulnDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.vulnDBDirectory = dir
	}
}

func WithClamAVDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.clamavDBDirectory = dir
	}
}

func WithMalwareScanTargetDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.malwareScanTargetDirectory = dir
	}
}

func WithOverrideHostname(hostname string) OptFunc {
	return func(o *opts) {
		o.overrideHostname = hostname
	}
}

func WithLogger(l *slog.Logger) OptFunc {
	return func(o *opts) {
		if l == nil {
			return
		}
		o.logger = l
	}
}

func defaultOpts() opts {
	rootfs, err := util.FindRootFS()
	if err != nil {
		slog.LogAttrs(
			context.TODO(),
			slog.LevelWarn,
			"failed to determine rootfs",
			slog.String("error", err.Error()),
		)
	}
	return opts{
		vulnDBDirectory:            "/var/lib/accuknox-omni/",
		clamavDBDirectory:          "/var/lib/clamav",
		malwareScanEnabled:         true,
		vulnScanEnabled:            true,
		malwareScanTargetDirectory: rootfs,
		logger:                     slog.Default(),
	}
}
