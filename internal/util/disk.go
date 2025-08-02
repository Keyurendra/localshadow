package util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/jaypipes/ghw"
	"golang.org/x/sys/unix"
)

func ListUnmountedPartitions(ctx context.Context) ([]ghw.Partition, error) {
	block, err := ghw.Block()
	if err != nil {
		return nil, err
	}

	var partitions []ghw.Partition

	for _, disk := range block.Disks {
		for _, p := range disk.Partitions {
			if p.MountPoint == "" {
				partitions = append(partitions, *p)
			}
		}
	}

	return partitions, nil
}

func MountRO(ctx context.Context, partition, baseMountPoint, fsTyp string) (string, error) {
	mountPoint := filepath.Join(baseMountPoint, uuid.New().String())
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return "", fmt.Errorf("creating mountpoint %q: %w", mountPoint, err)
	}
	err := unix.Mount(partition, mountPoint, fsTyp, unix.MS_RDONLY, "")
	if err != nil {
		return "", err
	}
	return mountPoint, nil
}

func Unmount(ctx context.Context, mountPoint string) error {
	err := unix.Unmount(mountPoint, unix.MNT_FORCE)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(mountPoint); err != nil {
		return fmt.Errorf("removing mountpoint %q: %w", mountPoint, err)
	}
	return nil
}

func Sha256Hash(x string) string {
	hash := sha256.Sum256([]byte(x))
	return hex.EncodeToString(hash[:])
}
