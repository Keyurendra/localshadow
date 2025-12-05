package scanner

import "context"

type Scanner interface {
	Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (Findings, error)
}

type Findings interface {
	DataType() string
}
