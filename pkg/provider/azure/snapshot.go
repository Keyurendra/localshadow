package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/google/uuid"

	"github.com/Keyurendra/shadowtest/pkg/resource"
)

func (p *Provider) ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) {
	var snapshosts []resource.Snapshot

	pager := p.snapClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("requesting next snapshot page: %w", err)
		}
		for _, snap := range page.Value {
			if snap.ID == nil {
				continue
			}
			if snap.Location == nil || !strings.EqualFold(*snap.Location, p.location) {
				continue
			}
			snapshosts = append(snapshosts, resource.Snapshot{
				URI: *snap.ID,
			})
		}
	}

	return snapshosts, nil
}

func (p *Provider) CreateSnapshot(ctx context.Context, diskURI string) (string, error) {
	name := identifierPrefix + "-" + uuid.NewString()
	createOpt := armcompute.DiskCreateOptionCopy
	poller, err := p.snapClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupFromURI(diskURI),
		name,
		armcompute.Snapshot{
			Location: &p.location,
			Properties: &armcompute.SnapshotProperties{
				CreationData: &armcompute.CreationData{
					CreateOption:     &createOpt,
					SourceResourceID: &diskURI,
				},
			},
		},
		nil,
	)
	if err != nil {
		return "", err
	}

	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("waiting for snapshot to be ready: %w", err)
	}

	return *result.ID, nil
}

func (p *Provider) WaitSnapshotReady(ctx context.Context, snapshotURI string) error {
	tick := time.NewTicker(time.Second * 2)
	defer tick.Stop()

	snapName := nameFromURI(snapshotURI)

Wait:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			resp, err := p.snapClient.Get(
				ctx,
				resourceGroupFromURI(snapshotURI),
				snapName,
				nil,
			)
			if err != nil {
				return fmt.Errorf("querying snapshot %s status: %w", snapshotURI, err)
			}

			if resp.Properties == nil || resp.Properties.ProvisioningState == nil {
				return fmt.Errorf("snapshot state is missing")
			}

			state := *resp.Properties.ProvisioningState
			switch state {
			case "Updating":
				continue Wait
			case "Failed":
				return fmt.Errorf("snapshot failed")
			case "Succeeded":
				return nil
			case "Deleting":
				return fmt.Errorf("snapshot is being deleted")
			default:
				return fmt.Errorf("unexpected snapshot state: %s", state)
			}
		}
	}
}

func (p *Provider) ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error) {
	name := identifierPrefix + "-" + uuid.NewString()
	createOpt := armcompute.DiskCreateOptionCopy
	poller, err := p.diskClient.BeginCreateOrUpdate(
		ctx,
		resourceGroupFromURI(snapshotURI),
		name,
		armcompute.Disk{
			Location: &p.location,
			Zones:    []*string{&p.zone},
			Properties: &armcompute.DiskProperties{
				CreationData: &armcompute.CreationData{
					CreateOption:     &createOpt,
					SourceResourceID: &snapshotURI,
				},
			},
		},
		nil,
	)
	if err != nil {
		return "", err
	}

	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("waiting for disk to be created: %w", err)
	}

	return *result.ID, nil
}

func (p *Provider) DeleteSnapshot(ctx context.Context, snapshotURI string) error {
	name := nameFromURI(snapshotURI)
	rg := resourceGroupFromURI(snapshotURI)

	poller, err := p.snapClient.BeginDelete(ctx, rg, name, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("waiting for snapshot to be deleted: %w", err)
	}
	return nil
}
