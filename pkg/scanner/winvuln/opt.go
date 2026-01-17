package winvuln

type OptFunc func(*opts)

type opts struct {
	useOfflineMode bool
	dbPath         string
}

func WithUseOfflineMode() OptFunc {
	return func(o *opts) {
		o.useOfflineMode = true
	}
}

func WithDBPath(dbPath string) OptFunc {
	return func(o *opts) {
		o.dbPath = dbPath
	}
}

func defaultOpts() opts {
	return opts{
		useOfflineMode: false,
		dbPath:         "/root/.cache/msrc/db.sqlite3",
	}
}
