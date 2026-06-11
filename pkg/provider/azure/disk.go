package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"

	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/util"
)

func (p *Provider) AttachDisk(ctx context.Context, diskURI, vmURI string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	vmRG := resourceGroupFromURI(vmURI)
	vmName := nameFromURI(vmURI)

	oldDevices, err := util.ListBlockDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("enumerating currently attached devices: %w", err)
	}

	host, err := p.vmClient.Get(ctx, vmRG, vmName, nil)
	if err != nil {
		return "", fmt.Errorf("querying host details: %w", err)
	}

	if host.Properties == nil || host.Properties.StorageProfile == nil {
		return "", fmt.Errorf("host storage profile is missing")
	}
	storage := host.Properties.StorageProfile

	var nextLUN int32 = 0
	usedLUNs := make(map[int32]bool)
	for _, disk := range storage.DataDisks {
		if disk.Lun != nil {
			usedLUNs[*disk.Lun] = true
		}
	}
	for usedLUNs[nextLUN] {
		nextLUN++
	}

	if storage.DataDisks == nil {
		storage.DataDisks = make([]*armcompute.DataDisk, 0)
	}
	createOpt := armcompute.DiskCreateOptionTypesAttach
	deleteOpt := armcompute.DiskDeleteOptionTypesDelete
	diskName := nameFromURI(diskURI)
	storage.DataDisks = append(storage.DataDisks, &armcompute.DataDisk{
		CreateOption: &createOpt,
		DeleteOption: &deleteOpt,
		Lun:          &nextLUN,
		Name:         &diskName,
		ManagedDisk: &armcompute.ManagedDiskParameters{
			ID: &diskURI,
		},
	})

	host.Properties.StorageProfile = storage

	poller, err := p.vmClient.BeginUpdate(
		ctx,
		vmRG,
		vmName,
		armcompute.VirtualMachineUpdate{
			Identity:   host.Identity,
			Properties: host.Properties,
			Plan:       host.Plan,
			Tags:       host.Tags,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("updating host VM: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("waiting for host VM to be updated: %w", err)
	}

	newDevices, err := util.ListBlockDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("enumerating newly attached devices: %w", err)
	}

	m := make(map[string]struct{})
	for _, dev := range oldDevices {
		m[dev] = struct{}{}
	}
	for _, dev := range newDevices {
		if _, found := m[dev]; !found {
			return dev, nil
		}
	}

	return "", fmt.Errorf("volume attached but device not found on fs")
}

func (p *Provider) DetachDisk(ctx context.Context, diskURI, vmURI string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	vmRG := resourceGroupFromURI(vmURI)
	vmName := nameFromURI(vmURI)

	host, err := p.vmClient.Get(ctx, vmRG, vmName, nil)
	if err != nil {
		return fmt.Errorf("querying host details: %w", err)
	}

	if host.Properties == nil || host.Properties.StorageProfile == nil {
		return fmt.Errorf("host storage profile is missing")
	}
	storage := host.Properties.StorageProfile

	updatedDisks := make([]*armcompute.DataDisk, 0)
	var found bool
	for _, disk := range storage.DataDisks {
		if disk.ManagedDisk == nil || disk.ManagedDisk.ID == nil {
			continue
		}
		if *disk.ManagedDisk.ID == diskURI {
			found = true
			continue
		}
		updatedDisks = append(updatedDisks, disk)
	}
	if !found {
		return fmt.Errorf("%s disk not found", diskURI)
	}
	host.Properties.StorageProfile.DataDisks = updatedDisks

	poller, err := p.vmClient.BeginUpdate(
		ctx,
		vmRG,
		vmName,
		armcompute.VirtualMachineUpdate{
			Identity:   host.Identity,
			Plan:       host.Plan,
			Properties: host.Properties,
			Tags:       host.Tags,
			Zones:      host.Zones,
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("updating host VM: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("waiting for host VM to be updated: %w", err)
	}

	return nil
}

func (p *Provider) DeleteDisk(ctx context.Context, diskURI string) error {
	poller, err := p.diskClient.BeginDelete(
		ctx,
		resourceGroupFromURI(diskURI),
		nameFromURI(diskURI),
		nil,
	)
	if err != nil {
		return err
	}
	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("waiting for disk to be deleted: %w", err)
	}
	return nil
}

func (p *Provider) ListDisks(ctx context.Context) ([]resource.Disk, error) {
	var disks []resource.Disk

	pager := p.diskClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("requesting next disk page: %w", err)
		}
		for _, disk := range page.Value {
			if disk.Location == nil || !strings.EqualFold(*disk.Location, p.location) {
				continue
			}
			disks = append(disks, resource.Disk{
				URI: *disk.ID,
			})
		}
	}

	return disks, nil
}

func (p *Provider) ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	vmRG := resourceGroupFromURI(vmURI)
	vmName := nameFromURI(vmURI)

	host, err := p.vmClient.Get(ctx, vmRG, vmName, nil)
	if err != nil {
		return nil, fmt.Errorf("querying host details: %w", err)
	}

	if host.Properties == nil || host.Properties.StorageProfile == nil {
		return nil, fmt.Errorf("host storage profile is missing")
	}

	storage := host.Properties.StorageProfile
	if storage.OSDisk == nil {
		return nil, fmt.Errorf("host VM is missing boot disk")
	}

	var disks []resource.Disk
	disks = append(disks, resource.Disk{
		URI: *storage.OSDisk.ManagedDisk.ID,
	})

	for _, disk := range storage.DataDisks {
		disks = append(disks, resource.Disk{
			URI: *disk.ManagedDisk.ID,
		})
	}

	return disks, nil
}

func (p *Provider) ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	return []resource.Disk{}, nil
}

func (p *Provider) ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) {
	var disks []resource.Disk

	pager := p.diskClient.NewListPager(nil)
	if pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("requesting next disk page: %w", err)
		}
		for _, disk := range page.Value {
			if disk.Location == nil || !strings.EqualFold(*disk.Location, p.location) {
				continue
			}
			if disk.ID == nil || disk.Properties == nil {
				continue
			}
			state := disk.Properties.DiskState
			if state == nil {
				continue
			}
			if *state == armcompute.DiskStateUnattached {
				disks = append(disks, resource.Disk{
					URI: *disk.ID,
				})
			}
		}
	}

	return disks, nil
}

func (p *Provider) WaitDiskReady(ctx context.Context, diskURI string) error {
	tick := time.NewTicker(time.Second * 2)
	defer tick.Stop()

	diskRG := resourceGroupFromURI(diskURI)
	diskName := nameFromURI(diskURI)

Wait:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			resp, err := p.diskClient.Get(ctx, diskRG, diskName, nil)
			if err != nil {
				return fmt.Errorf("querying disk %s status: %w", diskName, err)
			}

			if resp.Properties == nil || resp.Properties.ProvisioningState == nil {
				return fmt.Errorf("disk state is missing")
			}

			state := *resp.Properties.ProvisioningState
			switch state {
			case "Updating":
				continue Wait
			case "Failed":
				return fmt.Errorf("disk creation failed")
			case "Succeeded":
				return nil
			case "Deleting":
				return fmt.Errorf("disk is being deleted")
			default:
				return fmt.Errorf("unexpected disk state: %s", state)
			}
		}
	}
}
