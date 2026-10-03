//go:build linux

package winvuln

import (
	"context"
	"fmt"

	"github.com/Keyurendra/shadowtest/pkg/scanner"
)

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

type s struct {
	opts
}

func NewScanner(fns ...OptFunc) scanner.Scanner {
	o := opts{}
	for _, fn := range fns {
		fn(&o)
	}
	return &s{opts: o}
}

func (s s) Scan(
	ctx context.Context,
	mountpoint, vmURI, platform, osType string,
) (scanner.Findings, error) {
	return nil, fmt.Errorf("Windows vulnerability scanning is not supported in a Linux build")
}
