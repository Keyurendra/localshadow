package container

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestCRIInfoUsesContainerImage(t *testing.T) {
	t.Parallel()

	ctr := &runtimeapi.Container{
		Id: "id-1",
		Metadata: &runtimeapi.ContainerMetadata{
			Name: "nginx",
		},
		Image: &runtimeapi.ImageSpec{
			Image: "nginx:1.27",
		},
		ImageRef: "sha256:ctr",
		Labels: map[string]string{
			"app":                    "nginx",
			"io.kubernetes.pod.name": "webhook",
		},
		CreatedAt: 1000,
		State:     runtimeapi.ContainerState_CONTAINER_RUNNING,
	}
	status := &runtimeapi.ContainerStatus{
		Image:    &runtimeapi.ImageSpec{Image: "nginx:status"},
		ImageRef: "sha256:status",
	}

	info := criInfo(
		context.Background(),
		ctr,
		status,
		"containerd",
		"unix:///run/containerd/containerd.sock",
		nil,
	)
	assert.Equal(t, "nginx:1.27", info.Image)
	assert.Equal(t, "sha256:ctr", info.ImageID)
	assert.Equal(t, "running", info.State)
	assert.Equal(t, "containerd", info.Runtime)
}

func TestCRIInfoFallbackToStatusImage(t *testing.T) {
	t.Parallel()

	ctr := &runtimeapi.Container{Id: "id-2", ImageRef: "sha256:ctr"}
	status := &runtimeapi.ContainerStatus{
		Image:    &runtimeapi.ImageSpec{Image: "redis:7"},
		ImageRef: "sha256:status",
	}

	info := criInfo(
		context.Background(),
		ctr,
		status,
		"crio",
		"unix:///var/run/crio/crio.sock",
		nil,
	)
	assert.Equal(t, "redis:7", info.Image)
	assert.Equal(t, "sha256:status", info.ImageID)
}

func TestCRIInfoStatusImageUsesContainerRef(t *testing.T) {
	t.Parallel()

	ctr := &runtimeapi.Container{Id: "id-2", ImageRef: "sha256:ctr"}
	status := &runtimeapi.ContainerStatus{
		Image: &runtimeapi.ImageSpec{Image: "redis:7"},
	}

	info := criInfo(
		context.Background(),
		ctr,
		status,
		"crio",
		"unix:///var/run/crio/crio.sock",
		nil,
	)
	assert.Equal(t, "redis:7", info.Image)
	assert.Equal(t, "sha256:ctr", info.ImageID)
}

func TestCRIInfoFallbackToImageRef(t *testing.T) {
	t.Parallel()

	ctr := &runtimeapi.Container{Id: "id-3", ImageRef: "sha256:only"}

	info := criInfo(
		context.Background(),
		ctr,
		nil,
		"crio",
		"unix:///var/run/crio/crio.sock",
		nil,
	)
	assert.Equal(t, "sha256:only", info.Image)
	assert.Equal(t, "sha256:only", info.ImageID)
}

func TestResolveCRIRefPrefersRepoDigest(t *testing.T) {
	t.Parallel()

	cli := fakeImageServiceClient{
		resp: &runtimeapi.ImageStatusResponse{
			Image: &runtimeapi.Image{
				Id:          "sha256:image",
				RepoTags:    []string{"nginx:latest"},
				RepoDigests: []string{"docker.io/library/nginx@sha256:abc"},
			},
		},
	}
	image, id := resolveCRIRef(context.Background(), cli, "sha256:ctr", "sha256:ctr")
	assert.Equal(t, "docker.io/library/nginx@sha256:abc", image)
	assert.Equal(t, "sha256:image", id)
}

func TestResolveCRIRefUsesRepoTagWhenDigestMissing(t *testing.T) {
	t.Parallel()

	cli := fakeImageServiceClient{
		resp: &runtimeapi.ImageStatusResponse{
			Image: &runtimeapi.Image{
				Id:       "sha256:image",
				RepoTags: []string{"nginx:latest"},
			},
		},
	}
	image, id := resolveCRIRef(context.Background(), cli, "sha256:ctr", "sha256:ctr")
	assert.Equal(t, "nginx:latest", image)
	assert.Equal(t, "sha256:image", id)
}

type fakeImageServiceClient struct {
	resp *runtimeapi.ImageStatusResponse
	err  error
}

func (f fakeImageServiceClient) ImageFsInfo(context.Context, *runtimeapi.ImageFsInfoRequest, ...grpc.CallOption) (*runtimeapi.ImageFsInfoResponse, error) {
	return nil, nil
}

func (f fakeImageServiceClient) ListImages(context.Context, *runtimeapi.ListImagesRequest, ...grpc.CallOption) (*runtimeapi.ListImagesResponse, error) {
	return nil, nil
}

func (f fakeImageServiceClient) StreamImages(context.Context, *runtimeapi.StreamImagesRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[runtimeapi.StreamImagesResponse], error) {
	return nil, nil
}

func (f fakeImageServiceClient) ImageStatus(context.Context, *runtimeapi.ImageStatusRequest, ...grpc.CallOption) (*runtimeapi.ImageStatusResponse, error) {
	return f.resp, f.err
}

func (f fakeImageServiceClient) PullImage(context.Context, *runtimeapi.PullImageRequest, ...grpc.CallOption) (*runtimeapi.PullImageResponse, error) {
	return nil, nil
}

func (f fakeImageServiceClient) RemoveImage(context.Context, *runtimeapi.RemoveImageRequest, ...grpc.CallOption) (*runtimeapi.RemoveImageResponse, error) {
	return nil, nil
}
