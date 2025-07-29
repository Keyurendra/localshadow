package job

type OptFunc func(*opts)

type opts struct {
	mountpoint      string
	trivyEnabled    bool
	clamscanEnabled bool
}

func WithMountPoint(mountpoint string) OptFunc {
	return func(o *opts) {
		o.mountpoint = mountpoint
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

func defaultOpts() opts {
	return opts{
		mountpoint:      "/mnt/accuknox",
		clamscanEnabled: true,
		trivyEnabled:    true,
	}
}
