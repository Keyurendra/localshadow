package job

import (
	"log/slog"
	"runtime"
)

type OptFunc func(*opts)

type opts struct {
	baseMountPoint        string
	trivyEnabled          bool
	clamscanEnabled       bool
	concurrency           uint
	logger                *slog.Logger
	prometheusMetrics     bool
	prometheusMetricsPort uint16
}

func WithBaseMountPoint(baseMountPoint string) OptFunc {
	return func(o *opts) {
		o.baseMountPoint = baseMountPoint
	}
}

func WithClamscanDisabled() OptFunc {
	return func(o *opts) {
		o.clamscanEnabled = false
	}
}

func WithTrivyDisabled() OptFunc {
	return func(o *opts) {
		o.trivyEnabled = false
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
		baseMountPoint:        "/accuknox",
		clamscanEnabled:       true,
		trivyEnabled:          true,
		concurrency:           uint(runtime.NumCPU()),
		logger:                slog.Default(),
		prometheusMetrics:     false,
		prometheusMetricsPort: 9100,
	}
}
