package container

import (
	"fmt"
	"os"
	"time"
)

type OptFunc func(*opts)

type opts struct {
	timeout           time.Duration
	cacheDir          string
	runtimeOnly       bool
	runtimeArtifactDB string
	criSockets        []string
	remoteFallback    bool
	mountpoint        string
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

func WithRuntimeOnly() OptFunc {
	return func(o *opts) {
		o.runtimeOnly = true
	}
}

func WithRuntimeArtifactDB(dbPath string) OptFunc {
	return func(o *opts) {
		o.runtimeArtifactDB = dbPath
	}
}

func WithCRISockets(socketPaths ...string) OptFunc {
	return func(o *opts) {
		o.criSockets = socketPaths
	}
}

func WithRemoteFallback() OptFunc {
	return func(o *opts) {
		o.remoteFallback = true
	}
}

// WithMountpoint should only be used for agent-less scanning.
func WithMountpoint(mountpoint string) OptFunc {
	return func(o *opts) {
		o.mountpoint = mountpoint
	}
}

func defaultOpts() (*opts, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("get user cache directory: %w", err)
	}
	return &opts{
		timeout:           time.Hour * 12,
		cacheDir:          cacheDir,
		runtimeOnly:       false,
		runtimeArtifactDB: "/var/lib/accuknox-omni/runtime.db",
		remoteFallback:    false,
	}, nil
}
