package agentless

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

type overlayMount struct {
	root   string
	merged string
}

type mountCache struct {
	items map[string]*overlayMount
}

func newMountCache() *mountCache {
	return &mountCache{items: make(map[string]*overlayMount)}
}

func (c *mountCache) ensure(key string, build func() (*overlayMount, error)) (string, error) {
	if m, ok := c.items[key]; ok {
		return m.merged, nil
	}
	m, err := build()
	if err != nil {
		return "", err
	}
	c.items[key] = m
	return m.merged, nil
}

func (c *mountCache) cleanup() error {
	var out error
	for _, m := range c.items {
		out = errors.Join(out, cleanupOverlayMount(m))
	}
	return out
}

func mountKeyFromPath(mountpoint string) string {
	key := path.Base(path.Clean(mountpoint))
	if key == "" || key == "." || key == "/" {
		key = strings.Trim(path.Clean(mountpoint), "/")
	}
	if key == "" {
		key = "mount"
	}
	return strings.ReplaceAll(key, "/", "_")
}

func sanitizeImageKey(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "sha256:")
	if v == "" {
		return "image"
	}
	var b strings.Builder
	for _, ch := range v {
		if ch >= 'a' && ch <= 'z' {
			b.WriteRune(ch)
			continue
		}
		if ch >= 'A' && ch <= 'Z' {
			b.WriteRune(ch)
			continue
		}
		if ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
			continue
		}
		if ch == '-' || ch == '_' || ch == '.' {
			b.WriteRune(ch)
		}
	}
	if b.Len() == 0 {
		return "image"
	}
	return b.String()
}

func overlay2LowerDirs(dataRoot, imageID string) ([]string, v1.ConfigFile, error) {
	cfgPath, err := overlay2ConfigPath(dataRoot, imageID)
	if err != nil {
		return nil, v1.ConfigFile{}, err
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, v1.ConfigFile{}, fmt.Errorf("read image config %q: %w", cfgPath, err)
	}

	var cfg v1.ConfigFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, v1.ConfigFile{}, fmt.Errorf("decode image config %q: %w", cfgPath, err)
	}
	if len(cfg.RootFS.DiffIDs) == 0 {
		return nil, v1.ConfigFile{}, fmt.Errorf("no diff_ids in image config %q", cfgPath)
	}

	diffIDs := make([]digest.Digest, 0, len(cfg.RootFS.DiffIDs))
	for _, diff := range cfg.RootFS.DiffIDs {
		diffIDs = append(diffIDs, digest.Digest(diff.String()))
	}

	var lower []string
	for i, diff := range diffIDs {
		chain := identity.ChainID(diffIDs[:i+1]).String()
		chainID := strings.TrimPrefix(chain, "sha256:")
		cachePath := filepath.Join(
			dataRoot,
			"image",
			"overlay2",
			"layerdb",
			"sha256",
			chainID,
			"cache-id",
		)
		if _, err := os.Stat(cachePath); err != nil {
			// Some older setups may use diff_id keys directly.
			diffID := strings.TrimPrefix(diff.String(), "sha256:")
			altPath := filepath.Join(
				dataRoot,
				"image",
				"overlay2",
				"layerdb",
				"sha256",
				diffID,
				"cache-id",
			)
			if _, altErr := os.Stat(altPath); altErr == nil {
				cachePath = altPath
			}
		}
		cacheID, err := os.ReadFile(cachePath)
		if err != nil {
			return nil, v1.ConfigFile{}, fmt.Errorf("read cache-id %q: %w", cachePath, err)
		}
		layer := filepath.Join(dataRoot, "overlay2", strings.TrimSpace(string(cacheID)), "diff")
		if st, err := os.Stat(layer); err != nil || !st.IsDir() {
			return nil, v1.ConfigFile{}, fmt.Errorf("overlay layer %q missing", layer)
		}
		lower = append(lower, layer)
	}

	for i, j := 0, len(lower)-1; i < j; i, j = i+1, j-1 {
		lower[i], lower[j] = lower[j], lower[i]
	}
	return lower, cfg, nil
}

func overlay2ConfigPath(dataRoot, imageID string) (string, error) {
	id := strings.TrimPrefix(strings.TrimSpace(imageID), "sha256:")
	if id == "" {
		return "", errors.New("image id is empty")
	}
	p := filepath.Join(dataRoot, "image", "overlay2", "imagedb", "content", "sha256", id)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("overlay2 image config %q: %w", p, err)
	}
	return p, nil
}
