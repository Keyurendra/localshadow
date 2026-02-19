package scanner

import "log/slog"

type OptFunc func(*opts)

type opts struct {
	useExternalTrivy   bool
	malwareScanEnabled bool
	vulnScanEnabled    bool
	vulnDBDirectory    string
	clamavDBDirectory  string
	logger             *slog.Logger
}

func WithUseExternalTrivy() OptFunc {
	return func(o *opts) {
		o.useExternalTrivy = true
	}
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

func WithLogger(l *slog.Logger) OptFunc {
	return func(o *opts) {
		if l == nil {
			return
		}
		o.logger = l
	}
}

func defaultOpts() opts {
	return opts{
		useExternalTrivy:   false,
		malwareScanEnabled: true,
		vulnScanEnabled:    true,
		vulnDBDirectory:    "/var/lib/accuknox-omni",
		clamavDBDirectory:  "/var/lib/clamav",
		logger:             slog.Default(),
	}
}
