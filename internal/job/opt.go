package job

import "runtime"

type OptFunc func(*opts)

type opts struct {
	baseMountPoint  string
	trivyEnabled    bool
	clamscanEnabled bool
	concurrency     uint
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
			concurrency = 1
		}
		o.concurrency = concurrency
	}
}

func defaultOpts() opts {
	return opts{
		baseMountPoint:  "/mnt/accuknox",
		clamscanEnabled: true,
		trivyEnabled:    true,
		concurrency:     uint(runtime.NumCPU()),
	}
}
