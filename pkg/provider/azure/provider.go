package azure

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"

	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/util"
)

type Provider struct {
	opts
	location   string
	zone       string
	vmClient   *armcompute.VirtualMachinesClient
	diskClient *armcompute.DisksClient
	snapClient *armcompute.SnapshotsClient
	mu         sync.Mutex
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

func (p *Provider) GetName() string {
	return "azure"
}

func (p *Provider) Init(ctx context.Context) error {
	id, err := queryIMDS(ctx)
	if err != nil {
		return fmt.Errorf("querying azure imds: %w", err)
	}
	p.location = id.Location
	p.zone = id.Zone
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"azure metadata identified",
		slog.String("subscription_id", id.SubscriptionID),
		slog.String("location", id.Location),
		slog.String("resource_group", id.ResourceGroupName),
	)

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("creating azure credentials: %w", err)
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(id.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("creating azure VM client: %w", err)
	}
	p.vmClient = vmClient

	diskClient, err := armcompute.NewDisksClient(id.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("creating azure disk client: %w", err)
	}
	p.diskClient = diskClient

	snapClient, err := armcompute.NewSnapshotsClient(id.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("creating azure snapshot client: %w", err)
	}
	p.snapClient = snapClient

	return nil
}

func (p *Provider) PruneDangling(ctx context.Context) error {
	partitions, err := util.ListMountedPartitions(ctx)
	if err != nil {
		return fmt.Errorf("listing mounted partitions")
	}
	for _, part := range partitions {
		disk := part.Disk.Name
		if disk == "sda" || disk == "xvda" || disk == "nvme0n1" {
			continue
		}
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"unmounting partition from host",
			slog.String("partiton", "/dev/"+part.Name),
		)
		util.Unmount(ctx, "/dev/"+part.Name)
	}

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
				`detaching disk %q from host %q: %w`,
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
		err := p.DeleteSnapshot(ctx, s.URI)
		if err != nil {
			return fmt.Errorf("deleting snapshot %q: %w", s.URI, err)
		}
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
		err := p.DeleteDisk(ctx, d.URI)
		if err != nil {
			return fmt.Errorf("deleting snapshot %q: %w", d.URI, err)
		}
	}

	return nil
}
