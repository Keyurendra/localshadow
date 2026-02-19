package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/accuknox/omniscan/pkg/scanner"
)

type s struct {
	opts
	// nsCache is per-scan state to avoid repeated namespace API calls
	// on the same runtime socket while keeping scan attempts consistent.
	mu      sync.RWMutex
	nsCache map[string][]string
}

func NewScanner(fns ...OptFunc) (scanner.MultiScanner, error) {
	o, err := defaultOpts()
	if err != nil {
		return nil, fmt.Errorf("initializing opts: %w", err)
	}
	for _, fn := range fns {
		fn(o)
	}
	return &s{
		opts:    *o,
		nsCache: make(map[string][]string),
	}, nil
}

func (s *s) Scan(ctx context.Context, mountpoint, vmURI, platform, osType string, pub scanner.Publish) error {
	if s.mountpoint != "" {
		return s.scanAgentless(ctx, s.mountpoint, vmURI, platform, osType, pub)
	}

	infos, err := s.listRunning(ctx)
	if err != nil {
		return fmt.Errorf("listing running containers: %w", err)
	}
	s.resetNamespaceCache()

	targets := dedup(infos)
	slog.InfoContext(
		ctx,
		"prepared deduplicated container scan targets",
		slog.Int("containers", len(infos)),
		slog.Int("unique_images", len(targets)),
	)

	var scanErr error
	for _, t := range targets {
		f, err := s.scanTarget(ctx, t, vmURI, platform, osType)
		if err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf(
				"image %q: %w",
				t.image,
				err,
			))
			slog.ErrorContext(
				ctx,
				"failed to scan container image",
				slog.String("image", t.image),
				slog.String("dedup_key", t.key),
				slog.Int("containers", t.n),
				slog.Any("error", err),
			)
			continue
		}

		if pub != nil && f != nil {
			err := pub(ctx, f)
			if err != nil {
				scanErr = errors.Join(scanErr, err)
				slog.ErrorContext(
					ctx,
					"failed to publish container image finding",
					slog.String("image", t.image),
					slog.String("dedup_key", t.key),
					slog.Any("error", err),
				)
				continue
			}
		}

		slog.InfoContext(
			ctx,
			"successfully scanned container image",
			slog.String("image", t.image),
			slog.String("dedup_key", t.key),
			slog.Int("containers", t.n),
		)
	}

	return scanErr
}

// scanTarget keeps scan/publish semantics at unique-image granularity.
// This avoids duplicate work while preserving one error per deduped image.
func (s *s) scanTarget(ctx context.Context, t target, vmURI, platform, osType string) (scanner.Findings, error) {
	var scanErr error
	for _, src := range t.srcs {
		ns, err := s.nsFor(ctx, src)
		if err != nil {
			slog.WarnContext(
				ctx,
				"failed to resolve containerd namespaces",
				slog.String("runtime_host", src.host),
				slog.Any("error", err),
			)
		}

		f, err := s.scanOne(ctx, src.img, src.runtime, src.host, ns, vmURI, platform, osType)
		if err == nil {
			return f, nil
		}
		scanErr = errors.Join(scanErr, fmt.Errorf(
			"source %q on %q: %w",
			src.runtime,
			src.host,
			err,
		))
	}

	if scanErr != nil {
		return nil, scanErr
	}
	return nil, fmt.Errorf("no scan source for image %q", t.image)
}

// nsFor resolves namespace candidates once per runtime host and reuses
// them for all images in the same scan run.
func (s *s) nsFor(ctx context.Context, src source) ([]string, error) {
	if src.runtime != "containerd" {
		return nil, nil
	}
	if ns, ok := s.cachedNamespaces(src.host); ok {
		return ns, nil
	}
	ns, err := nsList(ctx, src.host)
	if err != nil {
		return nil, err
	}
	s.cacheNamespaces(src.host, ns)
	return ns, nil
}
