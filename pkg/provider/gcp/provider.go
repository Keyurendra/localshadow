package gcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/accuknox/omniscan/pkg/provider"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/metadata"
)

type Provider struct {
	opts
	project   string
	zone      string
	region    string
	instances *compute.InstancesClient
	disks     *compute.DisksClient
	snapshots *compute.SnapshotsClient
	metadata  *metadata.Client
}

func NewProvider(fns ...OptFunc) (provider.Provider, error) {
	o := defaultOpts()
	for _, f := range fns {
		err := f(&o)
		if err != nil {
			return nil, err
		}
	}
	return &Provider{opts: o}, nil
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
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		fmt.Sprintf("GCP project identified as %s", project),
	)

	zone, err := p.metadata.ZoneWithContext(ctx)
	if err != nil {
		return fmt.Errorf("querying GCP zone from metadata svc: %w", err)
	}
	p.zone = zone
	p.region = regionFromZone(zone)
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		fmt.Sprintf("GCP zone as %s", zone),
	)

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

func (p Provider) PruneDangling(ctx context.Context) error {
	host, err := p.GetCurrentVM(ctx)
	if err != nil {
		return fmt.Errorf("fetching host: %w", err)
	}
	for idx := 1; idx < len(host.Disks); idx++ {
		disk := host.Disks[idx]
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"detaching dangling disk from host",
			slog.String("disk_uri", disk.URI),
			slog.String("host_uri", host.URI),
		)
		err := p.DetachDisk(ctx, disk.URI, host.URI)
		if err != nil {
			return fmt.Errorf(
				"detaching disk %q from host %q: %w",
				host.URI, disk.URI, err,
			)
		}
	}

	snaps, err := p.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}
	for _, s := range snaps {
		if !strings.HasPrefix(nameFromURI(s.URI), identifierPrefix+"-") {
			continue
		}
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"deleting dangling snapshot",
			slog.String("snapshot_uri", s.URI),
		)
		p.DeleteSnapshot(ctx, s.URI)
	}

	disks, err := p.ListUnattachedDisks(ctx)
	if err != nil {
		return fmt.Errorf("listing unattached disks: %w", err)
	}
	for _, d := range disks {
		if !strings.HasPrefix(nameFromURI(d.URI), identifierPrefix+"-") {
			continue
		}
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"deleting dangling disk",
			slog.String("disk_uri", d.URI),
		)
		p.DeleteDisk(ctx, d.URI)
	}

	return nil
}
