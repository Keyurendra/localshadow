package util

import (
	"context"
	"fmt"
)

func MountRO(ctx context.Context, partition, baseMountPoint, fsTyp string) (string, error) {
	return "", fmt.Errorf("unsupported")
}

func Unmount(ctx context.Context, mountPoint string) error {
	return fmt.Errorf("unsupported")
}
