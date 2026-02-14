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
	sockets := parseSockets(s.criSockets)
	if len(sockets) > 0 {
		return detectFromSockets(statFn, hosts, sockets)
	}

	var cfgs []runtimeConfig
	seen := make(map[string]struct{})
	for _, rt := range hosts {
		for _, host := range rt.hosts {
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
				name:     rt.name,
				host:     host,
				cri:      rt.cri,
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
		host, path := normSocket(socket)
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

		rt, ok := runtimeFromPath(path, hosts)
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
			name:     rt.name,
			host:     host,
			cri:      rt.cri,
			explicit: true,
		})
	}

	if len(cfgs) == 0 && detectErr == nil {
		return nil, fmt.Errorf("no sockets provided in --cri-sockets")
	}
	return cfgs, detectErr
}

func parseSockets(values []string) []string {
	var sockets []string
	for _, value := range values {
		for socket := range strings.SplitSeq(value, ",") {
			socket = strings.TrimSpace(socket)
			if socket == "" {
				continue
			}
			sockets = append(sockets, socket)
		}
	}
	return sockets
}

func normSocket(socket string) (host, path string) {
	path = strings.TrimSpace(socket)
	path = strings.TrimPrefix(path, "unix://")
	if path == "" {
		return "", ""
	}
	return "unix://" + path, path
}

// sockKey canonicalizes equivalent socket paths (for example /var/run
// and /run) to prevent duplicate runtime probing.
func sockKey(host string) string {
	_, path := normSocket(host)
	path = filepath.Clean(path)
	if after, ok := strings.CutPrefix(path, "/var/run/"); ok {
		path = "/run/" + after
	}
	return "unix://" + path
}

func runtimeFromPath(path string, hosts []runtimeHost) (*runtimeHost, bool) {
	path = strings.ToLower(path)
	for _, rt := range hosts {
		for _, token := range rt.tokens {
			if strings.Contains(path, token) {
				r := rt
				return &r, true
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
	return strings.Contains(msg, "code = Unimplemented") &&
		strings.Contains(msg, "runtime.v1.RuntimeService")
}
