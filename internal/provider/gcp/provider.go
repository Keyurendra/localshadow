package gcp

import (
	"context"
	"fmt"

	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/resource"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/metadata"
)

type Provider struct {
	project   string
	zone      string
	filter    resource.PrecompiledFilter
	instances *compute.InstancesClient
	disks     *compute.DisksClient
	snapshots *compute.SnapshotsClient
	metadata  *metadata.Client
}

func NewProvider(vmFilter *resource.Filter) (provider.Provider, error) {
	if vmFilter == nil {
		return &Provider{}, nil
	}
	regFilter, err := vmFilter.Precompile()
	if err != nil {
		return nil, fmt.Errorf("precompiled provided filter: %w", err)
	}
	return &Provider{
		filter: *regFilter,
	}, nil
}

func (p Provider) GetName() string {
	return "gcp"
}

func (p *Provider) Init(ctx context.Context) error {
	var err error

	p.metadata = metadata.NewWithOptions(nil)

	if !p.metadata.OnGCEWithContext(ctx) {
		return fmt.Errorf("not running on GCP")
	}

	project, err := p.metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return fmt.Errorf("querying GCP project id from metadata svc: %w", err)
	}
	p.project = project

	zone, err := p.metadata.ZoneWithContext(ctx)
	if err != nil {
		return fmt.Errorf("querying GCP zone from metadata svc: %w", err)
	}
	p.zone = zone

	p.instances, err = compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("creating gcp compute instance client: %w", err)
	}

	p.disks, err = compute.NewDisksRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("creating gcp compute disk client: %w", err)
	}

	p.snapshots, err = compute.NewSnapshotsRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("creating gcp compute snapshot client: %w", err)
	}

	return nil
}
