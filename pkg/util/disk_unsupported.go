//go:build !linux

package util

import (
	"context"
	"fmt"
)

func MountRO(context.Context, string, string, string) (string, error) {
	return "", fmt.Errorf("mounting cloud disks is unsupported on this OS")
}

func Unmount(context.Context, string) error {
	return fmt.Errorf("unmounting cloud disks is unsupported on this OS")
}
