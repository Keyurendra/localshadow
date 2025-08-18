package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/util"

	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

func (p Provider) AttachDisk(ctx context.Context, diskURI, vmURI string) (string, error) {
	name := util.Sha256Hash(diskURI)
	op, err := p.instances.AttachDisk(ctx, &computepb.AttachDiskInstanceRequest{
		Project:  p.project,
		Zone:     zoneFromURI(vmURI),
		Instance: nameFromURI(vmURI),
		AttachedDiskResource: &computepb.AttachedDisk{
			Source:     &diskURI,
			DeviceName: &name,
		},
	})
	if err != nil {
		return "", err
	}

	if err := op.Wait(ctx); err != nil {
		return "", fmt.Errorf("waiting for disk to be mounted: %w", err)
	}

	parts, err := util.ListUnmountedPartitions(ctx)
	if err != nil {
		return "", fmt.Errorf("listing unmounted partitions: %w", err)
	}

	for _, p := range parts {
		if p.Disk.SerialNumber == name {
			return "/dev/" + p.Disk.Name, nil
		}
	}

	return "", fmt.Errorf("no attached disk matches the supplied gcp device name")
}

func (p Provider) DetachDisk(ctx context.Context, diskURI, vmURI string) error {
	i, err := p.instances.Get(ctx, &computepb.GetInstanceRequest{
		Project:  p.project,
		Zone:     zoneFromURI(vmURI),
		Instance: nameFromURI(vmURI),
	})
	if err != nil {
		return fmt.Errorf("fetching disk detail: %w", err)
	}

	var deviceName string
	for _, disk := range i.Disks {
		if disk.GetSource() == diskURI {
			deviceName = disk.GetDeviceName()
			break
		}
	}
	if deviceName == "" {
		return fmt.Errorf("disk %q not found", diskURI)
	}

	op, err := p.instances.DetachDisk(ctx, &computepb.DetachDiskInstanceRequest{
		Project:    p.project,
		Zone:       zoneFromURI(vmURI),
		Instance:   nameFromURI(vmURI),
		DeviceName: deviceName,
	})
	if err != nil {
		return err
	}

	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("waiting for disk to be unmounted: %w", err)
	}

	return nil
}

func (p Provider) DeleteDisk(ctx context.Context, diskURI string) error {
	op, err := p.disks.Delete(ctx, &computepb.DeleteDiskRequest{
		Project: p.project,
		Zone:    zoneFromURI(diskURI),
		Disk:    nameFromURI(diskURI),
	})
	if err != nil {
		return err
	}

	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("waiting for disk to be deleted: %w", err)
	}

	return nil
}

func (p Provider) ListDisks(ctx context.Context) ([]resource.Disk, error) {
	iter := p.disks.AggregatedList(ctx, &computepb.AggregatedListDisksRequest{
		Project: p.project,
	})

	var disks []resource.Disk

	for {
		page, err := iter.Next()
		if err != nil {
			if errors.Is(err, iterator.Done) {
				break
			}
			return nil, fmt.Errorf("fetching compute disks: %w", err)
		}
		for _, d := range page.Value.GetDisks() {
			disks = append(disks, resource.Disk{
				URI: d.GetSelfLink(),
			})
		}
	}

	return disks, nil
}

func (p Provider) ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	i, err := p.instances.Get(ctx, &computepb.GetInstanceRequest{
		Project:  p.project,
		Zone:     zoneFromURI(vmURI),
		Instance: nameFromURI(vmURI),
	})
	if err != nil {
		return nil, fmt.Errorf("fetching instance by id: %w", err)
	}

	var disks []resource.Disk

	for _, disk := range i.Disks {
		detail, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
			Project: p.project,
			Zone:    zoneFromURI(vmURI),
			Disk:    disk.GetDeviceName(),
		})
		if err != nil {
			return nil, fmt.Errorf("fetching details for %q: %w", disk.GetSource(), err)
		}
		disks = append(disks, resource.Disk{
			URI: detail.GetSelfLink(),
		})
	}

	return disks, nil
}

func (p Provider) ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	all, err := p.ListVMDisks(ctx, vmURI)
	if err != nil {
		return nil, fmt.Errorf("fetching all disks for %q: %w", vmURI, err)
	}

	var unattached []resource.Disk

	for _, d := range all {
		res, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
			Project: p.project,
			Zone:    zoneFromURI(d.URI),
			Disk:    nameFromURI(d.URI),
		})
		if err != nil {
			return nil, fmt.Errorf("fetching disk by id: %w", err)
		}
		if len(res.GetUsers()) == 0 {
			unattached = append(unattached, resource.Disk{
				URI: res.GetSelfLink(),
			})
		}
	}

	return unattached, nil
}

func (p Provider) ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) {
	all, err := p.ListDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching all disks: %w", err)
	}

	var unattached []resource.Disk

	for _, d := range all {
		res, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
			Project: p.project,
			Zone:    zoneFromURI(d.URI),
			Disk:    nameFromURI(d.URI),
		})
		if err != nil {
			return nil, fmt.Errorf("fetching disk by id: %w", err)
		}
		if len(res.GetUsers()) == 0 {
			unattached = append(unattached, resource.Disk{
				URI: res.GetSelfLink(),
			})
		}
	}

	return unattached, nil
}

func (p Provider) WaitDiskReady(ctx context.Context, diskURI string) error {
	tick := time.NewTicker(time.Second * 2)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			disk, err := p.disks.Get(ctx, &computepb.GetDiskRequest{
				Project: p.project,
				Zone:    zoneFromURI(diskURI),
				Disk:    nameFromURI(diskURI),
			})
			if err != nil {
				return fmt.Errorf("fetching disk details: %w", err)
			}
			if disk.GetStatus() == "READY" {
				return nil
			}
		}
	}
}
