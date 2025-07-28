package util

import (
	"context"

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

func MountRO(ctx context.Context, partition, to, fsTyp string) error {
	return unix.Mount(partition, to, fsTyp, unix.MS_RDONLY, "")
}

func Unmount(ctx context.Context, mountPoint string) error {
	return unix.Unmount(mountPoint, unix.MNT_FORCE)
}
