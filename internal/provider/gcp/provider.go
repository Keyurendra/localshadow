package gcp

import (
	"context"
	"fmt"

	"github.com/accuknox/omniscan/pkg/provider"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/metadata"
)

type Provider struct {
	project   string
	zone      string
	instances *compute.InstancesClient
	disks     *compute.DisksClient
	snapshots *compute.SnapshotsClient
	metadata  *metadata.Client
}

func NewProvider() provider.Provider {
	return &Provider{}
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
