package aws

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/accuknox/omniscan/pkg/provider/resource"
)

type OptFunc func(*opts) error

type opts struct {
	vmFilter     resource.PrecompiledFilter
	logger       *slog.Logger
	waitDeadline time.Duration
}

func WithVMFilter(f resource.Filter) OptFunc {
	return func(o *opts) error {
		pre, err := f.Precompile()
		if err != nil {
			return fmt.Errorf("precompiling provided VM filter: %w", err)
		}
		o.vmFilter = *pre
		return nil
	}
}

func WithLogger(l *slog.Logger) OptFunc {
	return func(o *opts) error {
		if l == nil {
			return nil
		}
		o.logger = l
		return nil
	}
}

func WithWaitDeadline(deadline time.Duration) OptFunc {
	return func(o *opts) error {
		o.waitDeadline = deadline
		return nil
	}
}

func defaultOpts() opts {
	return opts{
		vmFilter:     resource.PrecompiledFilter{},
		logger:       slog.Default().With("provider", "aws"),
		waitDeadline: time.Minute * 15,
	}
}
