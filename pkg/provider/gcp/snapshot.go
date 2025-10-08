package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"

	"github.com/accuknox/omniscan/pkg/resource"
)

func (p Provider) ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) {
	iter := p.snapshots.List(ctx, &computepb.ListSnapshotsRequest{
		Project: p.project,
	})

	var snapshots []resource.Snapshot

	for {
		snap, err := iter.Next()
		if err != nil {
			if errors.Is(err, iterator.Done) {
				break
			}
			return nil, fmt.Errorf("fetching volume snapshot: %w", err)
		}
		snapshots = append(snapshots, resource.Snapshot{
			URI: snap.GetSelfLink(),
		})
	}

	return snapshots, nil
}

func (p Provider) CreateSnapshot(ctx context.Context, diskURI string) (string, error) {
	name := identifierPrefix + "-" + uuid.NewString()
	op, err := p.snapshots.Insert(ctx, &computepb.InsertSnapshotRequest{
		Project: p.project,
		SnapshotResource: &computepb.Snapshot{
			Name:       &name,
			SourceDisk: &diskURI,
		},
	})
	if err != nil {
		return "", err
	}
	if err := op.Wait(ctx); err != nil {
		return "", fmt.Errorf("waiting for snapshot to be created: %w", err)
	}
	return fmt.Sprintf(
		"https://www.googleapis.com/compute/v1/projects/%s/global/snapshots/%s",
		p.project,
		name,
	), nil
}

func (p Provider) WaitSnapshotReady(ctx context.Context, snapshotURI string) error {
	tick := time.NewTicker(time.Second * 2)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			snap, err := p.snapshots.Get(ctx, &computepb.GetSnapshotRequest{
				Project:  p.project,
				Snapshot: nameFromURI(snapshotURI),
			})
			if err != nil {
				return fmt.Errorf("fetching snapshot details: %w", err)
			}
			if snap.GetStatus() == "READY" {
				return nil
			}
		}
	}
}

func (p Provider) ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error) {
	name := identifierPrefix + "-" + uuid.NewString()
	op, err := p.disks.Insert(ctx, &computepb.InsertDiskRequest{
		Project: p.project,
		Zone:    p.zone,
		DiskResource: &computepb.Disk{
			Name:           &name,
			SourceSnapshot: &snapshotURI,
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating disk: %w", err)
	}

	if err := op.Wait(ctx); err != nil {
		return "", fmt.Errorf("waiting for disk to be created: %w", err)
	}

	return fmt.Sprintf(
		"https://www.googleapis.com/compute/v1/projects/%s/zones/%s/disks/%s",
		p.project, p.zone, name,
	), nil
}

func (p Provider) DeleteSnapshot(ctx context.Context, snapshotURI string) error {
	op, err := p.snapshots.Delete(ctx, &computepb.DeleteSnapshotRequest{
		Project:  p.project,
		Snapshot: nameFromURI(snapshotURI),
	})
	if err != nil {
		return err
	}
	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("waiting for snapshot to be deleted: %w", err)
	}
	return nil
}
