package scanner

import "context"

type Scanner interface {
	Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (Findings, error)
}

type MultiScanner interface {
	Scan(ctx context.Context, mountpoint, vmURI, platform, osType string, pub Publish) error
}

type Findings interface {
	DataType() string
}

type Publish func(context.Context, Findings) error
