package aws

import (
	"context"
	"fmt"

	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (p *Provider) ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) {
	var snapshots []resource.Snapshot

	iter := ec2.NewDescribeSnapshotsPaginator(p.ec2, &ec2.DescribeSnapshotsInput{})
	for iter.HasMorePages() {
		page, err := iter.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("querying snapshots from paginator: %w", err)
		}
		for _, snap := range page.Snapshots {
			snapshots = append(snapshots, resource.Snapshot{
				URI: *snap.SnapshotId,
			})
		}
	}

	return snapshots, nil
}

func (p *Provider) CreateSnapshot(ctx context.Context, diskURI string) (string, error) {
	name := identifierPrefix + "-" + util.NewIsoNanoSecIdentifier()
	snap, err := p.ec2.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    &diskURI,
		Description: aws.String("Managed-by AccuKnox Omni"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSnapshot,
				Tags: []types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}
	return *snap.SnapshotId, nil
}

func (p *Provider) WaitSnapshotReady(ctx context.Context, snapshotURI string) error {
	return ec2.NewSnapshotCompletedWaiter(p.ec2).Wait(
		ctx,
		&ec2.DescribeSnapshotsInput{
			SnapshotIds: []string{snapshotURI},
		},
		p.waitDeadline,
	)
}

func (p *Provider) ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error) {
	name := identifierPrefix + "-" + util.NewIsoNanoSecIdentifier()
	volume, err := p.ec2.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: &p.az,
		ClientToken:      &snapshotURI,
		SnapshotId:       &snapshotURI,
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeVolume,
				Tags: []types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
				},
			},
		},
	})
	if err != nil {
		return "", nil
	}
	return *volume.VolumeId, nil
}

func (p *Provider) DeleteSnapshot(ctx context.Context, snapshotURI string) error {
	_, err := p.ec2.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: &snapshotURI,
	})
	return err
}
