package agentless

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	containerdimages "github.com/containerd/containerd/images"
	containerdmeta "github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/platforms"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

type offlineContainerdStore struct {
	metaDB         string
	contentRoot    string
	snapshotMetaDB string
	snapshotsDir   string
}

type resolvedContainerdImage struct {
	ref         string
	imageID     string
	chainID     string
	snapshotKey string
	diffIDs     []string
	imageConfig v1.ConfigFile
	hasConfig   bool
}

func newOfflineContainerdStore(metaDB, contentRoot, snapDB, snaps string) (*offlineContainerdStore, error) {
	if _, err := os.Stat(metaDB); err != nil {
		return nil, fmt.Errorf("containerd metadata db %q: %w", metaDB, err)
	}
	if st, err := os.Stat(contentRoot); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("containerd content store %q missing", contentRoot)
	}
	return &offlineContainerdStore{
		metaDB:         metaDB,
		contentRoot:    contentRoot,
		snapshotMetaDB: snapDB,
		snapshotsDir:   snaps,
	}, nil
}

func (s *offlineContainerdStore) resolutionCount(containers []Container) int {
	var count int
	seen := make(map[string]struct{})
	_ = s.withImageStore(func(ctx context.Context, cs content.Store, imageStore containerdimages.Store) error {
		for _, c := range containers {
			k := keyOf(c)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			img, err := resolveContainerdImage(ctx, cs, imageStore, c)
			if err != nil {
				continue
			}
			if img != nil {
				count++
			}
		}
		return nil
	})
	return count
}

func (s *offlineContainerdStore) reconstruct(mountpoint string, c Container, cache *mountCache) (string, ImageMeta, error) {
	img, err := s.resolveImage(c)
	if err != nil {
		return "", ImageMeta{}, err
	}
	lower, err := s.snapshotLowerDirsFor(img)
	if err != nil {
		return "", ImageMeta{}, err
	}

	key := sanitizeImageKey(img.imageID)
	at, err := cache.ensure(key, func() (*overlayMount, error) {
		return mountOverlayLowerDirs(mountpoint, key, lower)
	})
	if err != nil {
		return "", ImageMeta{}, err
	}

	meta := ImageMeta{
		ImageRef:    img.ref,
		ImageID:     img.imageID,
		DiffIDs:     img.diffIDs,
		HasConfig:   img.hasConfig,
		ImageConfig: img.imageConfig,
	}
	meta.RepoTags, meta.RepoDigests = refsFromImage(img.ref)
	return at, meta, nil
}

func (s *offlineContainerdStore) resolveImage(c Container) (*resolvedContainerdImage, error) {
	var out *resolvedContainerdImage
	err := s.withImageStore(func(ctx context.Context, cs content.Store, imageStore containerdimages.Store) error {
		r, err := resolveContainerdImage(ctx, cs, imageStore, c)
		if err != nil {
			return err
		}
		out = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("container image not found")
	}
	return out, nil
}

func (s *offlineContainerdStore) withImageStore(fn func(context.Context, content.Store, containerdimages.Store) error) error {
	db, err := bolt.Open(s.metaDB, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("open containerd metadata db: %w", err)
	}
	defer db.Close()

	cs, err := local.NewStore(s.contentRoot)
	if err != nil {
		return fmt.Errorf("open containerd content store: %w", err)
	}

	mdb := containerdmeta.NewDB(db, cs, nil)
	imageStore := containerdmeta.NewImageStore(mdb)
	ctx := namespaces.WithNamespace(context.Background(), "moby")
	return fn(ctx, cs, imageStore)
}

func resolveContainerdImage(ctx context.Context, cs content.Store, imageStore containerdimages.Store, c Container) (*resolvedContainerdImage, error) {
	want := digestOf(c.ImageID)
	if want == "" {
		want = digestOf(c.Image)
	}

	for _, cand := range imageCandidates(c) {
		img, err := imageStore.Get(ctx, cand)
		if err == nil {
			if want != "" && !imageMatchesDigest(ctx, cs, img, want) {
				continue
			}
			return decodeContainerdImage(ctx, cs, img)
		}
	}

	if want == "" {
		return nil, errors.New("container image not found in containerd metadata")
	}

	imgs, err := imageStore.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containerd images: %w", err)
	}
	for _, m := range imgs {
		if imageMatchesDigest(ctx, cs, m, want) {
			return decodeContainerdImage(ctx, cs, m)
		}
	}
	return nil, errors.New("container image not found in containerd metadata")
}

func imageMatchesDigest(ctx context.Context, cs content.Store, img containerdimages.Image, want string) bool {
	if want == "" {
		return true
	}
	if strings.EqualFold(img.Target.Digest.String(), want) {
		return true
	}
	cfg, err := containerdimages.Config(ctx, cs, img.Target, platforms.Default())
	if err != nil {
		return false
	}
	return strings.EqualFold(cfg.Digest.String(), want)
}

func decodeContainerdImage(ctx context.Context, cs content.Store, img containerdimages.Image) (*resolvedContainerdImage, error) {
	cfgDesc, err := containerdimages.Config(ctx, cs, img.Target, platforms.Default())
	if err != nil {
		return nil, fmt.Errorf("resolve image config %q: %w", img.Name, err)
	}
	raw, err := content.ReadBlob(ctx, cs, cfgDesc)
	if err != nil {
		return nil, fmt.Errorf("read image config blob %q: %w", cfgDesc.Digest, err)
	}

	var cfg ocispec.Image
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode image config blob %q: %w", cfgDesc.Digest, err)
	}
	if len(cfg.RootFS.DiffIDs) == 0 {
		return nil, fmt.Errorf("image %q has empty diff_ids", img.Name)
	}

	chainID := identity.ChainID(cfg.RootFS.DiffIDs).String()
	var diffIDs []string
	for _, d := range cfg.RootFS.DiffIDs {
		diffIDs = append(diffIDs, d.String())
	}

	var cfgFile v1.ConfigFile
	hasCfg := json.Unmarshal(raw, &cfgFile) == nil

	return &resolvedContainerdImage{
		ref:         img.Name,
		imageID:     img.Target.Digest.String(),
		chainID:     chainID,
		snapshotKey: snapshotKeyFromImage(img),
		diffIDs:     diffIDs,
		imageConfig: cfgFile,
		hasConfig:   hasCfg,
	}, nil
}

func snapshotKeyFromImage(img containerdimages.Image) string {
	keys := []string{
		"containerd.io/gc.ref.snapshot.overlayfs",
		"containerd.io/gc.ref.snapshot",
	}
	for _, k := range keys {
		if v := strings.TrimSpace(img.Labels[k]); v != "" {
			return v
		}
	}
	return ""
}

func imageCandidates(c Container) []string {
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if slices.Contains(out, v) {
			return
		}
		out = append(out, v)
	}

	add(c.Image)
	add(c.ImageID)
	if d := digestOf(c.Image); d != "" {
		add(d)
	}
	if d := digestOf(c.ImageID); d != "" {
		add(d)
	}
	return out
}

func (s *offlineContainerdStore) snapshotLowerDirsFor(img *resolvedContainerdImage) ([]string, error) {
	var out error
	try := func(start string) ([]string, bool) {
		start = strings.TrimSpace(start)
		if start == "" {
			return nil, false
		}
		lower, err := s.snapshotLowerDirsByKey(start)
		if err == nil {
			return lower, true
		}
		out = errors.Join(out, fmt.Errorf("snapshot key %q: %w", start, err))
		return nil, false
	}

	if lower, ok := try(img.snapshotKey); ok {
		return lower, nil
	}
	if lower, ok := try(img.chainID); ok {
		return lower, nil
	}

	k, err := s.findSnapshotKeyByRef(img.chainID)
	if err == nil && k != "" {
		if lower, ok := try(k); ok {
			return lower, nil
		}
	}
	if err != nil {
		out = errors.Join(out, err)
	}

	if out != nil {
		return nil, out
	}
	return nil, errors.New("snapshot mapping not found")
}

func (s *offlineContainerdStore) snapshotLowerDirsByKey(startKey string) ([]string, error) {
	db, err := bolt.Open(s.snapshotMetaDB, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("open snapshot metadata db: %w", err)
	}
	defer db.Close()

	var lower []string
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("v1"))
		if root == nil {
			return errors.New("snapshot metadata bucket v1 missing")
		}
		snaps := root.Bucket([]byte("snapshots"))
		if snaps == nil {
			return errors.New("snapshot metadata bucket snapshots missing")
		}

		key := strings.TrimSpace(startKey)
		seen := make(map[string]struct{})
		for key != "" {
			if _, ok := seen[key]; ok {
				return fmt.Errorf("snapshot chain cycle at %q", key)
			}
			seen[key] = struct{}{}

			sb := snaps.Bucket([]byte(key))
			if sb == nil {
				return fmt.Errorf("snapshot key %q not found", key)
			}

			id, err := readSnapshotID(sb)
			if err != nil {
				return fmt.Errorf("snapshot key %q: %w", key, err)
			}
			fs := filepath.Join(s.snapshotsDir, strconv.FormatUint(id, 10), "fs")
			if st, err := os.Stat(fs); err != nil || !st.IsDir() {
				return fmt.Errorf("snapshot fs %q missing", fs)
			}
			lower = append(lower, fs)

			key = string(sb.Get([]byte("parent")))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(lower) == 0 {
		return nil, fmt.Errorf("no snapshot lowerdirs for key %q", startKey)
	}
	return lower, nil
}

func (s *offlineContainerdStore) findSnapshotKeyByRef(chainID string) (string, error) {
	if strings.TrimSpace(chainID) == "" {
		return "", nil
	}

	db, err := bolt.Open(s.snapshotMetaDB, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return "", fmt.Errorf("open snapshot metadata db: %w", err)
	}
	defer db.Close()

	var matches []string
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("v1"))
		if root == nil {
			return errors.New("snapshot metadata bucket v1 missing")
		}
		snaps := root.Bucket([]byte("snapshots"))
		if snaps == nil {
			return errors.New("snapshot metadata bucket snapshots missing")
		}

		return snaps.ForEach(func(k, v []byte) error {
			if v != nil {
				return nil
			}
			sb := snaps.Bucket(k)
			if sb == nil {
				return nil
			}
			lb := sb.Bucket([]byte("labels"))
			if lb == nil {
				return nil
			}
			if ref := string(lb.Get([]byte("containerd.io/snapshot.ref"))); ref == chainID {
				matches = append(matches, string(k))
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous snapshot mapping for chain %q", chainID)
	}
	return matches[0], nil
}

func readSnapshotID(sb *bolt.Bucket) (uint64, error) {
	raw := sb.Get([]byte("id"))
	if len(raw) == 0 {
		return 0, errors.New("snapshot id is missing")
	}
	id, n := binary.Uvarint(raw)
	if n <= 0 {
		return 0, errors.New("snapshot id is invalid")
	}
	return id, nil
}
