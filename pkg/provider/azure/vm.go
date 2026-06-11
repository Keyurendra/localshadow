package azure

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/accuknox/omniscan/pkg/resource"
)

func (p *Provider) ListVMs(ctx context.Context) ([]resource.VM, error) {
	var vms []resource.VM
	id, err := queryIMDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying azure imds: %w", err)
	}
	pager := p.vmClient.NewListByLocationPager(p.location, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("requesting next VM page: %w", err)
		}
		for _, vm := range page.Value {
			if vm.ID == nil || vm.Name == nil {
				continue
			}
			if vm.Properties == nil || vm.Properties.StorageProfile == nil {
				continue
			}
			if !p.vmFilter.MultiAZ {
				skipVM := true
				for _, z := range vm.Zones {
					p.logger.LogAttrs(
						ctx,
						slog.LevelDebug,
						"comparing zones",
						slog.String("vm_zone", *z),
						slog.String("omni_zone", id.Zone),
					)

					if *z == id.Zone {
						skipVM = false
					}
				}
				if skipVM {
					continue
				}
			}
			storage := vm.Properties.StorageProfile
			if storage.OSDisk == nil {
				continue
			}

			if r := p.vmFilter.Name; r != nil && !r.MatchString(*vm.Name) {
				p.logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					"vm name did not match the provided filter. Skipping...",
					slog.String("vm_uri", *vm.ID),
					slog.String("vm_name", *vm.Name),
				)
				continue
			}

			var match bool

		NextLabel:
			for k, v := range vm.Tags {
				for _, r := range p.vmFilter.Labels {
					if r.Key != nil && !r.Key.MatchString(k) {
						continue
					}
					if v != nil && r.Value != nil && !r.Value.MatchString(*v) {
						continue
					}
					match = true
					break NextLabel
				}
			}

			if !match && len(p.vmFilter.Labels) != 0 {
				p.logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					"vm labels did not match the provided filter. Skipping...",
					slog.String("vm_uri", *vm.ID),
					slog.Any("vm_labels", vm.Tags),
				)
				continue
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
			vms = append(vms, resource.VM{
				URI:   *vm.ID,
				Disks: disks,
			})
		}
	}

	return vms, nil
}

func (p *Provider) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	id, err := queryIMDS(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying azure imds: %w", err)
	}

	host, err := p.vmClient.Get(ctx, id.ResourceGroupName, id.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("querying host details: %w", err)
	}

	if host.ID == nil {
		return nil, fmt.Errorf("host VM ID is null")
	}

	if host.Properties == nil || host.Properties.StorageProfile == nil {
		return nil, fmt.Errorf("host VM is missing storage profile")
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

	return &resource.VM{
		URI:   *host.ID,
		Disks: disks,
	}, nil
}
