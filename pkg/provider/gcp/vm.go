package gcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"

	"github.com/Keyurendra/shadowtest/pkg/resource"
)

func (p Provider) ListVMs(ctx context.Context) ([]resource.VM, error) {
	iter := p.instances.AggregatedList(ctx, &computepb.AggregatedListInstancesRequest{
		Project: p.project,
	})

	var vms []resource.VM

	for {
		page, err := iter.Next()
		if err != nil {
			if errors.Is(err, iterator.Done) {
				break
			}
			return nil, fmt.Errorf("fetching compute instances: %w", err)
		}

		for _, i := range page.Value.GetInstances() {
			vmRegion := regionFromZone(zoneFromURI(i.GetZone()))
			vmZone := zoneFromURI(i.GetZone())
			if p.region != vmRegion {
				p.logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					"instance out of host region. Skipping...",
					slog.String("vm_uri", i.GetSelfLink()),
					slog.String("vm_name", i.GetName()),
					slog.String("vm_region", vmRegion),
					slog.String("host_region", p.region),
				)
				continue
			}
			if p.zone != vmZone && !p.vmFilter.MultiAZ {
				p.logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					"instance out of host availability zone. Skipping...",
					slog.String("vm_uri", i.GetSelfLink()),
					slog.String("vm_name", i.GetName()),
					slog.String("vm_zone", vmZone),
					slog.String("host_zone", p.zone),
				)
				continue
			}
			if r := p.vmFilter.Name; r != nil && !r.MatchString(i.GetName()) {
				p.logger.LogAttrs(
					ctx,
					slog.LevelDebug,
					"vm name did not match the provided filter. Skipping...",
					slog.String("vm_uri", i.GetSelfLink()),
					slog.String("vm_name", i.GetName()),
				)
				continue
			}

			var match bool

		NextLabel:
			for k, v := range i.GetLabels() {
				for _, r := range p.vmFilter.Labels {
					if r.Key != nil && !r.Key.MatchString(k) {
						continue
					}
					if r.Value != nil && !r.Value.MatchString(v) {
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
					slog.String("vm_uri", i.GetSelfLink()),
					slog.Any("vm_labels", i.GetLabels()),
				)
				continue
			}

			disks := make([]resource.Disk, len(i.Disks))
			for idx, disk := range i.Disks {
				disks[idx] = resource.Disk{
					URI: disk.GetSource(),
				}
			}

			vms = append(vms, resource.VM{
				URI:   i.GetSelfLink(),
				Disks: disks,
			})
		}
	}

	return vms, nil
}

func (p Provider) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	name, err := p.metadata.InstanceNameWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching instance id from metadata svc: %w", err)
	}

	i, err := p.instances.Get(ctx, &computepb.GetInstanceRequest{
		Instance: name,
		Project:  p.project,
		Zone:     p.zone,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching instance details: %w", err)
	}

	disks := make([]resource.Disk, len(i.Disks))
	for idx, disk := range i.Disks {
		disks[idx] = resource.Disk{
			URI: disk.GetSource(),
		}
	}

	return &resource.VM{
		URI:   i.GetSelfLink(),
		Disks: disks,
	}, nil
}
