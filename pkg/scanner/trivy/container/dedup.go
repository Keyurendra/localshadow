package container

import (
	"strings"
)

type source struct {
	img     string
	runtime string
	host    string
}

type target struct {
	key   string
	image string
	n     int
	srcs  []source
}

// dedup groups running containers by image identity so each unique
// image is scanned once even when many containers use it.
func dedup(containers []containerInfo) []target {
	var targets []target
	ix := make(map[string]int)
	seen := make(map[string]struct{})

	for _, c := range containers {
		k := keyOf(c)
		src := source{img: imgRef(c), runtime: c.Runtime, host: c.RuntimeHost}

		i, ok := ix[k]
		if !ok {
			ix[k] = len(targets)
			targets = append(targets, target{
				key:   k,
				image: imgRef(c),
				n:     1,
				srcs:  []source{src},
			})
			seen[k+"|"+srcKey(src)] = struct{}{}
			continue
		}

		targets[i].n++
		if targets[i].image == "" {
			targets[i].image = imgRef(c)
		}

		sk := k + "|" + srcKey(src)
		if _, ok := seen[sk]; ok {
			continue
		}
		seen[sk] = struct{}{}
		targets[i].srcs = append(targets[i].srcs, src)
	}

	return targets
}

// keyOf prioritizes digest-based identity over tag/ref identity because
// tags are mutable and can drift across runtimes over time.
func keyOf(c containerInfo) string {
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

func imgRef(c containerInfo) string {
	if image := strings.TrimSpace(c.Image); image != "" {
		return image
	}
	if id := strings.TrimSpace(c.ImageID); id != "" {
		return id
	}
	return c.ID
}

func srcKey(s source) string {
	return strings.Join([]string{s.runtime, s.host, s.img}, "|")
}

func uniqNS(items []string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(ns string) {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			return
		}
		if _, ok := seen[ns]; ok {
			return
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	for _, ns := range items {
		add(ns)
	}
	return out
}
