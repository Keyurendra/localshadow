package scanner

import "log/slog"

type OptFunc func(*opts)

type opts struct {
	malwareScanEnabled bool
	vulnScanEnabled    bool
	vulnDBDirectory    string
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

func WithVulnDBDirectory(dir string) OptFunc {
	return func(o *opts) {
		o.vulnDBDirectory = dir
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
		malwareScanEnabled: true,
		vulnScanEnabled:    true,
		vulnDBDirectory:    "/root/.cache/vulndb/",
		logger:             slog.Default(),
	}
}
