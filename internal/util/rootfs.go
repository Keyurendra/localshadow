package util

import (
	"os"
	"path/filepath"
)

func detectRootFS(mountPoint string, markers []string) float64 {
	var hits uint

	for _, dir := range markers {
		stats, err := os.Stat(filepath.Join(mountPoint, dir))
		if err != nil || !stats.IsDir() {
			continue
		}
		hits += 1
	}

	return float64(hits) / float64(len(markers))
}

func DetectLinuxRootFS(mountPoint string) float64 {
	return detectRootFS(mountPoint, []string{
		"etc", "bin", "sys", "lib", "usr",
	})
}

func DetectWindowsRootFS(mountPoint string) float64 {
	return detectRootFS(mountPoint, []string{
		"Windows", "Program Files", "Users",
	})
}
