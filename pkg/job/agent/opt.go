package agent

import "log/slog"

type OptFunc func(*opts)

type opts struct {
	vulnScanDBDir      string
	vulnScanEnabled    bool
	malwareScanEnabled bool
	logger             *slog.Logger
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

func WithVulnScanDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.vulnScanDBDir = dir
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
		vulnScanDBDir:      "/var/lib/accuknox-omni/",
		malwareScanEnabled: true,
		vulnScanEnabled:    true,
		logger:             slog.Default(),
	}
}
