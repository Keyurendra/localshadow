package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Keyurendra/shadowtest/pkg/scanner"
	"github.com/Keyurendra/shadowtest/pkg/scanner/trivy/container/agentless"
)

func (s *s) scanAgentless(ctx context.Context, mountpoint, vmURI, platform, osType string, pub scanner.Publish) error {
	containers, dataRoot, err := agentless.Inventory(mountpoint)
	if err != nil {
		return fmt.Errorf("listing running docker containers from disk: %w", err)
	}
	if len(containers) == 0 {
		slog.InfoContext(ctx, "no running docker containers found on mounted disk")
		return nil
	}

	resolver, err := agentless.NewResolver(mountpoint, mountpoint, dataRoot, containers)
	if err != nil {
		return fmt.Errorf("detecting container storage with certainty: %w", err)
	}
	slog.InfoContext(
		ctx,
		"detected agentless container image store",
		slog.String("store", string(resolver.Kind())),
	)

	infos := toContainerInfos(containers)
	targets := dedup(infos)
	groups := groupByDedupKey(containers)

	var scanErr error
	for _, t := range targets {
		g := groups[t.key]
		if len(g) == 0 {
			scanErr = errors.Join(scanErr, fmt.Errorf(
				"missing dedup group for key %q",
				t.key,
			))
			continue
		}

		f, err := s.scanAgentlessTarget(ctx, resolver, g[0], vmURI, platform, osType)
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
			if err := pub(ctx, f); err != nil {
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

	scanErr = errors.Join(scanErr, resolver.Cleanup())
	return scanErr
}

func (s *s) scanAgentlessTarget(ctx context.Context, resolver *agentless.Resolver, c agentless.Container, vmURI, platform, osType string) (scanner.Findings, error) {
	at, meta, err := resolver.Reconstruct(c)
	if err != nil {
		ref := strings.TrimSpace(c.Image)
		if ref == "" {
			ref = strings.TrimSpace(c.ImageID)
		}
		if s.remoteFallback && ref != "" {
			slog.WarnContext(
				ctx,
				"local agentless reconstruction failed, retrying remote image scan",
				slog.String("image", ref),
				slog.Any("error", err),
			)
			f, remErr := s.scanRemoteImage(ctx, ref, vmURI, platform, osType)
			if remErr == nil {
				return f, nil
			}
			return nil, errors.Join(err, remErr)
		}
		return nil, err
	}

	if strings.TrimSpace(meta.ImageRef) == "" {
		meta.ImageRef = strings.TrimSpace(c.ImageID)
	}
	return s.scanAgentlessRootFS(ctx, at, meta, vmURI, platform, osType)
}

func toContainerInfos(in []agentless.Container) []containerInfo {
	out := make([]containerInfo, 0, len(in))
	for _, c := range in {
		out = append(out, containerInfo{
			ID:          c.ID,
			Name:        c.Name,
			Image:       c.Image,
			ImageID:     c.ImageID,
			GraphDriver: c.GraphDriver,
			Runtime:     "docker",
			RuntimeHost: "agentless",
		})
	}
	return out
}

func groupByDedupKey(containers []agentless.Container) map[string][]agentless.Container {
	out := make(map[string][]agentless.Container)
	for _, c := range containers {
		k := keyOf(containerInfo{
			ID:      c.ID,
			Image:   c.Image,
			ImageID: c.ImageID,
		})
		out[k] = append(out[k], c)
	}
	return out
}
