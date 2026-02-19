package agentless

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type dockerDaemonConfig struct {
	DataRoot string `json:"data-root"`
}

type dockerContainerConfigV2 struct {
	ID          string                             `json:"ID"`
	Name        string                             `json:"Name"`
	Image       string                             `json:"Image"`
	Config      dockerContainerConfigV2Config      `json:"Config"`
	State       dockerContainerConfigV2State       `json:"State"`
	GraphDriver dockerContainerConfigV2GraphDriver `json:"GraphDriver"`
}

type dockerContainerConfigV2Config struct {
	Image string `json:"Image"`
}

type dockerContainerConfigV2State struct {
	Running bool `json:"Running"`
}

type dockerContainerConfigV2GraphDriver struct {
	Name string `json:"Name"`
}

func Inventory(rootfs string) ([]Container, string, error) {
	dataRoot, err := dockerDataRoot(rootfs)
	if err != nil {
		return nil, "", err
	}

	containersDir := filepath.Join(dataRoot, "containers")
	ents, err := os.ReadDir(containersDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, dataRoot, nil
		}
		return nil, dataRoot, fmt.Errorf("read docker containers dir: %w", err)
	}

	var running []Container
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		cfgPath := filepath.Join(containersDir, ent.Name(), "config.v2.json")
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			continue
		}

		var cfg dockerContainerConfigV2
		if err := json.Unmarshal(raw, &cfg); err != nil {
			continue
		}
		if !cfg.State.Running {
			continue
		}

		id := strings.TrimSpace(cfg.ID)
		if id == "" {
			id = ent.Name()
		}
		name := strings.TrimPrefix(strings.TrimSpace(cfg.Name), "/")
		image := strings.TrimSpace(cfg.Config.Image)
		if image == "" {
			image = strings.TrimSpace(cfg.Image)
		}

		running = append(running, Container{
			ID:          id,
			Name:        name,
			Image:       image,
			ImageID:     strings.TrimSpace(cfg.Image),
			GraphDriver: strings.TrimSpace(cfg.GraphDriver.Name),
		})
	}

	return running, dataRoot, nil
}

func dockerDataRoot(rootfs string) (string, error) {
	base := filepath.Join(rootfs, "var", "lib", "docker")
	daemonCfg := filepath.Join(rootfs, "etc", "docker", "daemon.json")
	raw, err := os.ReadFile(daemonCfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, nil
		}
		return "", fmt.Errorf("read docker daemon config: %w", err)
	}

	var cfg dockerDaemonConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("decode docker daemon config: %w", err)
	}
	if strings.TrimSpace(cfg.DataRoot) == "" {
		return base, nil
	}

	p := filepath.Clean(cfg.DataRoot)
	p = strings.TrimPrefix(p, string(os.PathSeparator))
	return filepath.Join(rootfs, p), nil
}
