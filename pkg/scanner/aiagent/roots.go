package aiagent

import (
	"os"
	"path/filepath"
)

func DiscoverRoots(mountpoint string, osType string) []string {
	switch osType {
	case "linux":
		return discoverLinuxRoots(mountpoint)
	default:
		return []string{mountpoint}
	}
}

func discoverLinuxRoots(mountpoint string) []string {
	candidates := []string{
		filepath.Join(mountpoint, "usr/bin"),
		filepath.Join(mountpoint, "usr/local/bin"),
		filepath.Join(mountpoint, "usr/lib"),
		filepath.Join(mountpoint, "usr/local/lib"),
		filepath.Join(mountpoint, "opt"),
		filepath.Join(mountpoint, "root"),
		filepath.Join(mountpoint, "home"),
	}

	var roots []string

	for _, root := range candidates {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			roots = append(roots, root)
		}
	}

	return roots
}
