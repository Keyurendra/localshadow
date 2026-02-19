package agentless

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Container struct {
	ID          string
	Name        string
	Image       string
	ImageID     string
	GraphDriver string
}

type ImageMeta struct {
	ImageRef    string
	ImageID     string
	DiffIDs     []string
	RepoTags    []string
	RepoDigests []string
	ImageConfig v1.ConfigFile
	HasConfig   bool
}

type StoreKind string

const (
	StoreOverlay2        StoreKind = "overlay2"
	StoreDockerContainer StoreKind = "docker-containerd"
	StoreSystemContainer StoreKind = "system-containerd"
)

func imageRef(c Container) string {
	if strings.TrimSpace(c.Image) != "" {
		return c.Image
	}
	return c.ImageID
}

func refsFromImage(ref string) ([]string, []string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil
	}
	if strings.Contains(ref, "@sha256:") {
		return nil, []string{ref}
	}
	return []string{ref}, nil
}

func keyOf(c Container) string {
	if d := digestOf(c.Image); d != "" {
		return "digest:" + d
	}
	if d := digestOf(c.ImageID); d != "" {
		return "digest:" + d
	}
	if ref := strings.TrimSpace(strings.ToLower(c.Image)); ref != "" {
		return "ref:" + ref
	}
	if id := strings.TrimSpace(strings.ToLower(c.ImageID)); id != "" {
		return "id:" + id
	}
	return "container:" + c.ID
}

func digestOf(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	i := strings.Index(v, "sha256:")
	if i < 0 {
		return ""
	}

	sum := v[i+len("sha256:"):]
	var b strings.Builder
	for _, ch := range sum {
		if !isHex(ch) {
			break
		}
		b.WriteRune(ch)
		if b.Len() == 64 {
			return "sha256:" + b.String()
		}
	}

	return ""
}

func isHex(ch rune) bool {
	if ch >= '0' && ch <= '9' {
		return true
	}
	if ch >= 'a' && ch <= 'f' {
		return true
	}
	return false
}
