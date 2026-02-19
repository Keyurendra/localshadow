package container

import (
	"os"
	"strings"
)

func retryRemote(runtime string, err error) bool {
	if runtime != "containerd" {
		return false
	}
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "content digest") && strings.Contains(msg, "not found")
}

// setContainerdEnv pins Trivy to the runtime socket that produced the image
// so local scans use the same containerd instance.
func setContainerdEnv(runtime, runtimeHost string) func() {
	if runtime != "containerd" {
		return func() {}
	}
	address := strings.TrimPrefix(runtimeHost, "unix://")
	if address == "" {
		return func() {}
	}
	return withEnv("CONTAINERD_ADDRESS", address)
}

func setContainerdNS(namespace string) func() {
	if namespace == "" {
		return func() {}
	}
	return withEnv("CONTAINERD_NAMESPACE", namespace)
}

func withEnv(key, value string) func() {
	old, hadOld := os.LookupEnv(key)
	_ = os.Setenv(key, value)
	return func() {
		if hadOld {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	}
}
