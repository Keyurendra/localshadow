package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	dockerContainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type containerInfo struct {
	ID          string
	Name        string
	Image       string
	ImageID     string
	Labels      map[string]string
	CreatedAt   time.Time
	Status      string
	State       string
	Ports       []dockerContainer.Port
	Mounts      []dockerContainer.MountPoint
	Runtime     string
	RuntimeHost string
}

func (s *s) listRunning(ctx context.Context) ([]containerInfo, error) {
	rts, detectErr := s.detectRuntimes()
	if detectErr != nil && len(rts) == 0 {
		return nil, detectErr
	}

	scanErr := detectErr
	var running []containerInfo
	for _, c := range rts {
		if c.cri {
			cts, err := listCRI(ctx, c.host, c.name)
			if err != nil {
				if !c.explicit && isCRIUnavailable(err) {
					slog.WarnContext(
						ctx,
						"skipping non-cri runtime endpoint",
						slog.String("runtime", c.name),
						slog.String("runtime_host", c.host),
						slog.Any("error", err),
					)
					continue
				}
				scanErr = errors.Join(scanErr, fmt.Errorf(
					"listing containers for runtime %q on %q: %w",
					c.name,
					c.host,
					err,
				))
				slog.ErrorContext(
					ctx,
					"failed to list runtime containers",
					slog.String("runtime", c.name),
					slog.String("runtime_host", c.host),
					slog.Any("error", err),
				)
				continue
			}
			running = append(running, cts...)
			continue
		}

		cts, err := listDocker(ctx, &c)
		if err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf(
				"listing containers for runtime %q on %q: %w",
				c.name,
				c.host,
				err,
			))
			slog.ErrorContext(
				ctx,
				"failed to list runtime containers",
				slog.String("runtime", c.name),
				slog.String("runtime_host", c.host),
				slog.Any("error", err),
			)
			continue
		}
		running = append(running, cts...)
	}

	if len(running) == 0 && scanErr != nil {
		return nil, scanErr
	}

	return running, scanErr
}

func listDocker(ctx context.Context, cfg *runtimeConfig) ([]containerInfo, error) {
	opts := []client.Opt{
		client.WithHost(cfg.host),
		client.WithAPIVersionNegotiation(),
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	ping, err := cli.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("ping docker daemon: %w", err)
	}
	slog.InfoContext(
		ctx,
		"daemon ping",
		slog.String("api_version", ping.APIVersion),
		slog.String("os", ping.OSType),
	)

	cts, err := cli.ContainerList(ctx, dockerContainer.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	imgCache := make(map[string]dockerImageRef)
	var running []containerInfo
	for _, c := range cts {
		var name string
		if len(c.Names) > 0 {
			name = c.Names[0]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}

		img, id := resolveDockerRef(ctx, cli, c.Image, c.ImageID, imgCache)
		running = append(running, containerInfo{
			ID:          c.ID,
			Name:        name,
			Image:       img,
			ImageID:     id,
			Labels:      c.Labels,
			CreatedAt:   time.Unix(c.Created, 0),
			Status:      c.Status,
			State:       c.State,
			Ports:       c.Ports,
			Mounts:      c.Mounts,
			Runtime:     cfg.name,
			RuntimeHost: cfg.host,
		})
	}

	return running, nil
}

type dockerImageRef struct {
	image string
	id    string
}

// resolveDockerRef inspects Docker image metadata to prefer immutable
// repo digests for dedup identity when available.
func resolveDockerRef(ctx context.Context, cli *client.Client, image, imageID string, cache map[string]dockerImageRef) (string, string) {
	keys := []string{
		strings.TrimSpace(imageID),
		strings.TrimSpace(image),
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if v, ok := cache[key]; ok {
			return v.image, v.id
		}
	}

	if cli == nil {
		return image, imageID
	}

	for _, key := range keys {
		if key == "" {
			continue
		}

		inspect, err := cli.ImageInspect(ctx, key)
		if err != nil {
			continue
		}

		res := dockerImageRef{
			image: pickRef(inspect.RepoDigests, inspect.RepoTags, image),
			id:    imageID,
		}
		if inspect.ID != "" {
			res.id = inspect.ID
		}

		for _, k := range keys {
			if k == "" {
				continue
			}
			cache[k] = res
		}
		return res.image, res.id
	}

	return image, imageID
}
