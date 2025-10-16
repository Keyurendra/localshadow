package util

import (
	"context"

	"github.com/jaypipes/ghw"
)

func ListBlockDevices(ctx context.Context) ([]string, error) {
	block, err := ghw.Block()
	if err != nil {
		return nil, err
	}

	devices := make([]string, len(block.Disks))
	for idx, disk := range block.Disks {
		devices[idx] = "/dev/" + disk.Name
	}

	return devices, nil
}

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

func ListMountedPartitions(ctx context.Context) ([]ghw.Partition, error) {
	block, err := ghw.Block()
	if err != nil {
		return nil, err
	}

	var partitions []ghw.Partition

	for _, disk := range block.Disks {
		for _, p := range disk.Partitions {
			if p.MountPoint != "" {
				partitions = append(partitions, *p)
			}
		}
	}

	return partitions, nil
}
