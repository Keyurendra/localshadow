package cloud

import (
	"log/slog"
	"runtime"
)

type OptFunc func(*opts)

type opts struct {
	baseMountPoint                   string
	useExternalTrivy                 bool
	vulnScanEnabled                  bool
	malwareScanEnabled               bool
	containerVulnScanEnabled         bool
	containerImageScanRemoteFallback bool
	clusterID                        *int
	clusterName                      string
	vulnDBDirectory                  string
	concurrency                      uint
	logger                           *slog.Logger
	prometheusMetrics                bool
	prometheusMetricsPort            uint16
}

func WithBaseMountPoint(baseMountPoint string) OptFunc {
	return func(o *opts) {
		o.baseMountPoint = baseMountPoint
	}
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

func WithContainerVulnScanEnabled() OptFunc {
	return func(o *opts) {
		o.containerVulnScanEnabled = true
	}
}

func WithContainerImageScanRemoteFallback() OptFunc {
	return func(o *opts) {
		o.containerImageScanRemoteFallback = true
	}
}

func WithClusterID(clusterID int) OptFunc {
	return func(o *opts) {
		o.clusterID = &clusterID
	}
}

func WithClusterName(clusterName string) OptFunc {
	return func(o *opts) {
		o.clusterName = clusterName
	}
}

func WithConcurrency(concurrency uint) OptFunc {
	return func(o *opts) {
		if concurrency == 0 {
			concurrency = uint(runtime.NumCPU())
		}
		o.concurrency = concurrency
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

// WithPrometheusMetrics enable prometheus metrics endpoint. Only applicable
// during scheduling.
func WithPrometheusMetrics() OptFunc {
	return func(o *opts) {
		o.prometheusMetrics = true
	}
}

// WithPrometheusMetricsPort sets the port for prometheus metrics server. Only
// applicable during scheduling.
func WithPrometheusMetricsPort(port uint16) OptFunc {
	return func(o *opts) {
		o.prometheusMetricsPort = port
	}
}

func defaultOpts() opts {
	return opts{
		baseMountPoint:                   "/accuknox",
		useExternalTrivy:                 false,
		malwareScanEnabled:               true,
		vulnScanEnabled:                  true,
		containerVulnScanEnabled:         false,
		containerImageScanRemoteFallback: false,
		vulnDBDirectory:                  "/var/lib/accuknox-omni",
		concurrency:                      uint(runtime.NumCPU()),
		logger:                           slog.Default(),
		prometheusMetrics:                false,
		prometheusMetricsPort:            9100,
	}
}
