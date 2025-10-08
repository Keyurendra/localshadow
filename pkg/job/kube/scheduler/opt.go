package scheduler

import "log/slog"

type OptFunc func(*opts)

type opts struct {
	logger *slog.Logger
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
		logger: slog.Default(),
	}
}
