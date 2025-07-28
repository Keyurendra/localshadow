package gcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/accuknox/omniscan/pkg/resource"

	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
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
