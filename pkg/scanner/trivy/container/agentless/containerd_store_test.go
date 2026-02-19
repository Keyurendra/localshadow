package agentless

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	containerdimages "github.com/containerd/containerd/images"
	containerdmeta "github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestContainerdStoreResolveImageAndSnapshotFS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	metaDB := filepath.Join(dir, "meta.db")
	contentRoot := filepath.Join(dir, "content")
	snapDB := filepath.Join(dir, "snapshot.db")
	snapsDir := filepath.Join(dir, "snapshots")

	require.NoError(t, os.MkdirAll(contentRoot, 0o755))
	require.NoError(t, os.MkdirAll(snapsDir, 0o755))
	require.NoError(t, os.WriteFile(snapDB, nil, 0o644))

	d := digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID, _ := writeTestContainerdImage(t, metaDB, contentRoot, "repo/app:1", []digest.Digest{d})
	writeTestSnapshotMeta(t, snapDB, chainID, 42, "")
	require.NoError(t, os.MkdirAll(filepath.Join(snapsDir, "42", "fs"), 0o755))

	st, err := newOfflineContainerdStore(metaDB, contentRoot, snapDB, snapsDir)
	require.NoError(t, err)

	img, err := st.resolveImage(Container{Image: "repo/app:1"})
	require.NoError(t, err)
	assert.Equal(t, "repo/app:1", img.ref)
	assert.Equal(t, chainID, img.chainID)

	lower, err := st.snapshotLowerDirsByKey(chainID)
	require.NoError(t, err)
	require.Len(t, lower, 1)
	assert.Equal(t, filepath.Join(snapsDir, "42", "fs"), lower[0])
}

func TestContainerdStoreResolveByConfigDigestImageID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	metaDB := filepath.Join(dir, "meta.db")
	contentRoot := filepath.Join(dir, "content")
	snapDB := filepath.Join(dir, "snapshot.db")
	snapsDir := filepath.Join(dir, "snapshots")

	require.NoError(t, os.MkdirAll(contentRoot, 0o755))
	require.NoError(t, os.MkdirAll(snapsDir, 0o755))
	require.NoError(t, os.WriteFile(snapDB, nil, 0o644))

	d := digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	chainID, cfgDigest := writeTestContainerdImage(
		t,
		metaDB,
		contentRoot,
		"repo/nginx:latest",
		[]digest.Digest{d},
	)
	writeTestSnapshotMeta(t, snapDB, chainID, 99, "")
	require.NoError(t, os.MkdirAll(filepath.Join(snapsDir, "99", "fs"), 0o755))

	st, err := newOfflineContainerdStore(metaDB, contentRoot, snapDB, snapsDir)
	require.NoError(t, err)

	img, err := st.resolveImage(Container{Image: "repo/nginx:latest", ImageID: cfgDigest})
	require.NoError(t, err)
	assert.Equal(t, chainID, img.chainID)
}

func writeTestContainerdImage(t *testing.T, metaDB, contentRoot, name string, diffIDs []digest.Digest) (string, string) {
	t.Helper()

	cs, err := local.NewStore(contentRoot)
	require.NoError(t, err)

	cfg := ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}}
	cfgRaw, err := json.Marshal(cfg)
	require.NoError(t, err)

	cfgDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromBytes(cfgRaw),
		Size:      int64(len(cfgRaw)),
	}
	require.NoError(t, content.WriteBlob(
		context.Background(),
		cs,
		"cfg-"+cfgDesc.Digest.String(),
		bytes.NewReader(cfgRaw),
		cfgDesc,
	))

	manifest := ocispec.Manifest{Config: cfgDesc}
	manifest.SchemaVersion = 2
	manifestRaw, err := json.Marshal(manifest)
	require.NoError(t, err)

	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestRaw),
		Size:      int64(len(manifestRaw)),
	}
	require.NoError(t, content.WriteBlob(
		context.Background(),
		cs,
		"manifest-"+manifestDesc.Digest.String(),
		bytes.NewReader(manifestRaw),
		manifestDesc,
	))

	db, err := bolt.Open(metaDB, 0o600, nil)
	require.NoError(t, err)
	defer db.Close()

	mdb := containerdmeta.NewDB(db, cs, nil)
	store := containerdmeta.NewImageStore(mdb)
	ctx := namespaces.WithNamespace(context.Background(), "moby")
	_, err = store.Create(ctx, containerdimages.Image{Name: name, Target: manifestDesc})
	require.NoError(t, err)

	return identity.ChainID(diffIDs).String(), cfgDesc.Digest.String()
}

func writeTestSnapshotMeta(t *testing.T, dbPath, key string, id uint64, parent string) {
	t.Helper()

	db, err := bolt.Open(dbPath, 0o600, nil)
	require.NoError(t, err)
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte("v1"))
		if err != nil {
			return err
		}
		snaps, err := root.CreateBucketIfNotExists([]byte("snapshots"))
		if err != nil {
			return err
		}
		sb, err := snaps.CreateBucketIfNotExists([]byte(key))
		if err != nil {
			return err
		}
		var buf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(buf[:], id)
		if err := sb.Put([]byte("id"), buf[:n]); err != nil {
			return err
		}
		if parent != "" {
			if err := sb.Put([]byte("parent"), []byte(parent)); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
}
