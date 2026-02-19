package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type runtimeHost struct {
	name   string
	cri    bool
	hosts  []string
	tokens []string
}

var runtimeHosts = []runtimeHost{
	{
		name: "docker",
		hosts: []string{
			"unix:///var/run/docker.sock",
			"unix:///run/docker.sock",
		},
		tokens: []string{"docker"},
	},
	{
		name: "podman",
		hosts: []string{
			"unix:///run/podman/podman.sock",
			"unix:///var/run/podman/podman.sock",
		},
		tokens: []string{"podman"},
	},
	{
		name: "containerd",
		cri:  true,
		hosts: []string{
			"unix:///run/containerd/containerd.sock",
			"unix:///var/run/containerd/containerd.sock",
			"unix:///run/k3s/containerd/containerd.sock",
		},
		tokens: []string{"containerd"},
	},
	{
		name: "crio",
		cri:  true,
		hosts: []string{
			"unix:///var/run/crio/crio.sock",
			"unix:///run/crio/crio.sock",
		},
		tokens: []string{"crio", "cri-o"},
	},
}

type runtimeConfig struct {
	name     string
	host     string
	cri      bool
	explicit bool
}

// detectRuntimes resolves socket candidates from explicit flags first,
// then falls back to default runtime sockets on the host.
func (s *s) detectRuntimes() ([]runtimeConfig, error) {
	return s.detectWithStat(os.Stat, runtimeHosts)
}

func (s *s) detectWithStat(statFn func(string) (os.FileInfo, error), hosts []runtimeHost) ([]runtimeConfig, error) {
	if len(s.criSockets) > 0 {
		return detectFromSockets(statFn, hosts, s.criSockets)
	}

	var cfgs []runtimeConfig
	seen := make(map[string]struct{})
	for _, runtime := range hosts {
		for _, host := range runtime.hosts {
			path := strings.TrimPrefix(host, "unix://")
			if _, err := statFn(path); err != nil {
				continue
			}
			k := sockKey(host)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			cfgs = append(cfgs, runtimeConfig{
				name:     runtime.name,
				host:     host,
				cri:      runtime.cri,
				explicit: false,
			})
		}
	}

	if len(cfgs) == 0 {
		return nil, fmt.Errorf(
			"no supported container runtime detected: docker, podman, containerd, crio",
		)
	}

	return cfgs, nil
}

func detectFromSockets(statFn func(string) (os.FileInfo, error), hosts []runtimeHost, sockets []string) ([]runtimeConfig, error) {
	var cfgs []runtimeConfig
	var detectErr error
	seen := make(map[string]struct{})

	for _, socket := range sockets {
		host, path := normalizeSocket(socket)
		if path == "" {
			continue
		}

		if _, err := statFn(path); err != nil {
			detectErr = errors.Join(detectErr, fmt.Errorf(
				"stat socket %q: %w",
				path,
				err,
			))
			continue
		}

		runtime, ok := runtimeFromPath(path, hosts)
		if !ok {
			detectErr = errors.Join(detectErr, fmt.Errorf(
				"failed to determine runtime from socket path %q, supported runtimes: docker, podman, containerd, crio",
				path,
			))
			continue
		}

		k := sockKey(host)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		cfgs = append(cfgs, runtimeConfig{
			name:     runtime.name,
			host:     host,
			cri:      runtime.cri,
			explicit: true,
		})
	}

	if len(cfgs) == 0 && detectErr == nil {
		return nil, fmt.Errorf("no sockets provided in --cri-sockets")
	}

	return cfgs, detectErr
}

func normalizeSocket(socket string) (host, path string) {
	path = strings.TrimSpace(socket)
	path = strings.TrimPrefix(path, "unix://")
	if path == "" {
		return "", ""
	}
	return "unix://" + path, path
}

// sockKey canonicalizes equivalent socket paths (for example /var/run and /run)
// to prevent duplicate runtime probing.
func sockKey(host string) string {
	_, path := normalizeSocket(host)
	path = filepath.Clean(path)
	if after, ok := strings.CutPrefix(path, "/var/run/"); ok {
		path = "/run/" + after
	}
	return "unix://" + path
}

func runtimeFromPath(path string, hosts []runtimeHost) (*runtimeHost, bool) {
	key := sockKey("unix://" + path)
	for _, runtime := range hosts {
		for _, host := range runtime.hosts {
			if sockKey(host) == key {
				return &runtime, true
			}
		}
	}

	lowerPath := strings.ToLower(path)
	for _, runtime := range hosts {
		for _, token := range runtime.tokens {
			if strings.Contains(lowerPath, token) {
				return &runtime, true
			}
		}
	}

	return nil, false
}

// isCRIUnavailable treats non-CRI endpoints as skippable when probing
// implicit runtime sockets to avoid noisy hard failures.
func isCRIUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "code = Unimplemented") && strings.Contains(msg, "runtime.v1.RuntimeService")
}
