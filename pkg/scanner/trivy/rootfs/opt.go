package rootfs

import (
	"fmt"
	"os"
	"time"
)

type OptFunc func(*opts)

type opts struct {
	timeout          time.Duration
	cacheDir         string
	useEmbeddedTrivy bool
}

func WithTimeout(timeout time.Duration) OptFunc {
	return func(o *opts) {
		o.timeout = timeout
	}
}

func WithCacheDirectory(cacheDir string) OptFunc {
	return func(o *opts) {
		o.cacheDir = cacheDir
	}
}

func WithUseEmbeddedTrivy(use bool) OptFunc {
	return func(o *opts) {
		o.useEmbeddedTrivy = use
	}
}

func defaultOpts() (*opts, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("get user cache directory: %w", err)
	}
	return &opts{
		timeout:          time.Hour * 12,
		cacheDir:         cacheDir,
		useEmbeddedTrivy: false,
	}, nil
}
