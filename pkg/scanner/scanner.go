package scanner

import (
	"context"
	"io"
)

type Scanner interface {
	Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (Findings, error)
}

type Findings interface {
	JSON() []byte
	JSONReader() io.Reader
	DataType() string
}
