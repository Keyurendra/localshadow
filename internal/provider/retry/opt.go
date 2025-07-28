package retry

import (
	"context"
	"time"

	"github.com/avast/retry-go/v4"
)

type OptFunc func(*opts)

type opts struct {
	attempts uint
	delay    time.Duration
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

func defaultOpts() opts {
	return opts{
		attempts: 10,
		delay:    time.Millisecond * 100,
	}
}

func (r Retry) opts(ctx context.Context) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.Attempts(r.o.attempts),
		retry.Delay(r.o.delay),
		retry.DelayType(retry.BackOffDelay),
	}
}
