package agentless

import (
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectStoreUsesSystemContainerdWhenDockerStoreMisses(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	dataRoot := filepath.Join(rootfs, "var", "lib", "docker")

	dockerMeta := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.metadata.v1.bolt", "meta.db")
	dockerContent := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.content.v1.content")
	dockerSnapDB := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.snapshotter.v1.overlayfs", "metadata.db")
	dockerSnaps := filepath.Join(dataRoot, "containerd", "daemon", "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	require.NoError(t, os.MkdirAll(filepath.Dir(dockerMeta), 0o755))
	require.NoError(t, os.WriteFile(dockerMeta, nil, 0o644))
	require.NoError(t, os.MkdirAll(dockerContent, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(dockerSnapDB), 0o755))
	require.NoError(t, os.WriteFile(dockerSnapDB, nil, 0o644))
	require.NoError(t, os.MkdirAll(dockerSnaps, 0o755))

	systemMeta := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.metadata.v1.bolt", "meta.db")
	systemContent := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.content.v1.content")
	systemSnapDB := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.snapshotter.v1.overlayfs", "metadata.db")
	systemSnaps := filepath.Join(rootfs, "var", "lib", "containerd", "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	require.NoError(t, os.MkdirAll(systemContent, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(systemMeta), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(systemSnapDB), 0o755))
	require.NoError(t, os.WriteFile(systemSnapDB, nil, 0o644))
	require.NoError(t, os.MkdirAll(systemSnaps, 0o755))

	d := digest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, _ = writeTestContainerdImage(
		t,
		systemMeta,
		systemContent,
		"repo/app:1",
		[]digest.Digest{d},
	)

	cts := []Container{{ID: "c1", Image: "repo/app:1"}}
	kind, _, err := detectStore(rootfs, dataRoot, cts)
	require.NoError(t, err)
	assert.Equal(t, StoreSystemContainer, kind)
}
