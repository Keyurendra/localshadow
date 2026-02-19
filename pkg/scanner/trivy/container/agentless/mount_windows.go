//go:build windows

package agentless

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

func cleanupOverlayMount(m *overlayMount) error {
	if m == nil {
		return nil
	}
	if err := os.RemoveAll(m.root); err != nil {
		return fmt.Errorf("remove temp root %q: %w", m.root, err)
	}
	return nil
}

func mountOverlayLowerDirs(_, _ string, lower []string) (*overlayMount, error) {
	if len(lower) == 0 {
		return nil, errors.New("overlay lowerdir list is empty")
	}
	return nil, fmt.Errorf("overlay mounts are not supported on %s", runtime.GOOS)
}
