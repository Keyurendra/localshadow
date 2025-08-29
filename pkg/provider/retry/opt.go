package retry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/avast/retry-go/v4"
)

type OptFunc func(*opts)

type opts struct {
	attempts uint
	delay    time.Duration
	logger   *slog.Logger
}

func WithAttempts(n uint) OptFunc {
	return func(o *opts) {
		o.attempts = n
	}
}

func WithDelay(delay time.Duration) OptFunc {
	return func(o *opts) {
		o.delay = delay
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
		attempts: 10,
		delay:    time.Millisecond * 100,
		logger:   slog.Default().With("provider", "retry"),
	}
}

func (r Retry) getRetryOpts(ctx context.Context) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.Attempts(r.attempts),
		retry.Delay(r.delay),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(attempt uint, err error) {
			r.logger.LogAttrs(
				ctx,
				slog.LevelError,
				fmt.Sprintf("retry attempt %d", attempt),
				slog.Any("error", err),
			)
		}),
	}
}
