package container

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func listCRI(ctx context.Context, host, runtime string) ([]containerInfo, error) {
	conn, err := grpc.NewClient(
		host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial cri socket: %w", err)
	}
	defer conn.Close()

	runCli := runtimeapi.NewRuntimeServiceClient(conn)
	imgCli := runtimeapi.NewImageServiceClient(conn)
	resp, err := runCli.ListContainers(ctx, &runtimeapi.ListContainersRequest{
		Filter: &runtimeapi.ContainerFilter{
			State: &runtimeapi.ContainerStateValue{
				State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing containers over cri: %w", err)
	}

	var running []containerInfo
	for _, ctr := range resp.GetContainers() {
		statusResp, err := runCli.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
			ContainerId: ctr.GetId(),
		})
		var status *runtimeapi.ContainerStatus
		if err != nil {
			slog.ErrorContext(
				ctx,
				"failed to inspect container over cri",
				slog.String("container_id", ctr.GetId()),
				slog.String("runtime", runtime),
				slog.Any("error", err),
			)
		}
		if statusResp != nil {
			status = statusResp.GetStatus()
		}
		running = append(running, criInfo(ctx, ctr, status, runtime, host, imgCli))
	}

	return running, nil
}

func criInfo(ctx context.Context, ctr *runtimeapi.Container, status *runtimeapi.ContainerStatus, runtime, host string, imgCli runtimeapi.ImageServiceClient) containerInfo {
	var name string
	if md := ctr.GetMetadata(); md != nil {
		name = md.GetName()
	}

	img, id := criImage(ctr, status)
	resolvedImg, resolvedID := resolveCRIRef(ctx, imgCli, img, id)
	if resolvedImg != "" {
		img = resolvedImg
		if resolvedID != "" {
			id = resolvedID
		}
	}

	state := strings.ToLower(strings.TrimPrefix(
		ctr.GetState().String(),
		"CONTAINER_",
	))

	return containerInfo{
		ID:          ctr.GetId(),
		Name:        name,
		Image:       img,
		ImageID:     id,
		Labels:      ctr.GetLabels(),
		CreatedAt:   time.Unix(0, ctr.GetCreatedAt()),
		Status:      ctr.GetState().String(),
		State:       state,
		Runtime:     runtime,
		RuntimeHost: host,
	}
}

func criImage(ctr *runtimeapi.Container, status *runtimeapi.ContainerStatus) (string, string) {
	if image := ctr.GetImage(); image != nil && image.GetImage() != "" {
		return image.GetImage(), ctr.GetImageRef()
	}

	if status != nil {
		image := status.GetImage()
		if image != nil && image.GetImage() != "" {
			if status.GetImageRef() != "" {
				return image.GetImage(), status.GetImageRef()
			}
			return image.GetImage(), ctr.GetImageRef()
		}
		if status.GetImageRef() != "" {
			return status.GetImageRef(), status.GetImageRef()
		}
	}

	if ctr.GetImageRef() != "" {
		return ctr.GetImageRef(), ctr.GetImageRef()
	}

	return "", ""
}

// resolveCRIRef enriches CRI image identity with repo digests/tags so
// dedup can align better across runtimes.
func resolveCRIRef(ctx context.Context, cli runtimeapi.ImageServiceClient, image, imageID string) (string, string) {
	if cli == nil {
		return "", ""
	}

	seen := make(map[string]struct{})
	candidates := []string{image, imageID}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}

		resp, err := cli.ImageStatus(ctx, &runtimeapi.ImageStatusRequest{
			Image: &runtimeapi.ImageSpec{Image: c},
		})
		if err != nil {
			continue
		}
		if resp == nil || resp.GetImage() == nil {
			continue
		}

		img := resp.GetImage()
		id := img.GetId()
		if id == "" {
			id = imageID
		}
		return pickRef(img.GetRepoDigests(), img.GetRepoTags(), ""), id
	}

	return "", ""
}

func pickRef(repoDigests, repoTags []string, fallback string) string {
	if len(repoDigests) > 0 && repoDigests[0] != "" {
		return repoDigests[0]
	}
	if len(repoTags) > 0 && repoTags[0] != "" {
		return repoTags[0]
	}
	return fallback
}
