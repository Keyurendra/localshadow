package util

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func FindRootFS() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if sd := os.Getenv("SystemDrive"); sd != "" {
			return sd + string(os.PathSeparator), nil
		}
		if sr := os.Getenv("SystemRoot"); sr != "" { // fallback
			if vol := filepath.VolumeName(sr); vol != "" {
				return vol + string(os.PathSeparator), nil
			}
		}
		if wd, err := os.Getwd(); err == nil { // final fallback
			if vol := filepath.VolumeName(wd); vol != "" {
				return vol + string(os.PathSeparator), nil
			}
		}
		return "", errors.New("unable to determine Windows root volume")
	default:
		return string(os.PathSeparator), nil
	}
}

func DetectOS(mountPoint string) string {
	linuxProb := detectLinuxRootFS(mountPoint)
	winProb := detectWindowsRootFS(mountPoint)
	if linuxProb < .5 && winProb < .5 {
		return "unknown"
	}
	if linuxProb > winProb {
		return "linux"
	}
	return "windows"
}

func detectLinuxRootFS(mountPoint string) float64 {
	return detectRootFS(mountPoint, []string{
		"etc", "bin", "sys", "lib", "usr",
	})
}

func detectWindowsRootFS(mountPoint string) float64 {
	return detectRootFS(mountPoint, []string{
		"Windows", "Program Files", "Users",
	})
}

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
