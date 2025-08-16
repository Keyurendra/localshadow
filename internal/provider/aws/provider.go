package aws

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type Provider struct {
	opts
	region    string
	az        string
	accountID string
	imds      *imds.Client
	ec2       *ec2.Client
	mu        sync.Mutex
}

func NewProvider(fns ...OptFunc) (provider.Provider, error) {
	o := defaultOpts()
	for _, f := range fns {
		err := f(&o)
		if err != nil {
			return nil, err
		}
	}
	return &Provider{
		opts: o,
	}, nil
}

func (p *Provider) GetName() string {
	return "aws"
}

func (p *Provider) Init(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading default config: %w", err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	p.imds = imdsClient

	region, err := imdsClient.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return fmt.Errorf("querying instance region from imds: %w", err)
	}
	p.region = region.Region
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		fmt.Sprintf("AWS region identified as %s", p.region),
	)

	id, err := imdsClient.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return fmt.Errorf("querying instance identity from imds: %w", err)
	}

	p.az = id.AvailabilityZone
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		fmt.Sprintf("AWS az identified as %s", p.az),
	)

	p.accountID = id.AccountID
	p.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		fmt.Sprintf("AWS account identified as %s", p.accountID),
	)

	cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(p.region))
	if err != nil {
		return fmt.Errorf("loading default config with region: %w", err)
	}
	p.ec2 = ec2.NewFromConfig(cfg)

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
		err := util.Unmount(ctx, "/dev/"+part.Name)
		if err != nil {
			return fmt.Errorf("unmounting partition %s: %w", "/dev/"+part.Name, err)
		}
	}

	host, err := p.GetCurrentVM(ctx)
	if err != nil {
		return fmt.Errorf("fetching host: %w", err)
	}
	for _, disk := range host.Disks {
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"detaching dangling disk from host",
			slog.String("disk_uri", disk.URI),
			slog.String("host_uri", host.URI),
		)
		p.DetachDisk(ctx, disk.URI, host.URI)
	}

	sIter := ec2.NewDescribeSnapshotsPaginator(p.ec2, &ec2.DescribeSnapshotsInput{})
	for sIter.HasMorePages() {
		page, err := sIter.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("request next snapshot page: %w", err)
		}
		for _, snap := range page.Snapshots {
			name := resourceNameFromTags(snap.Tags)
			if !strings.HasPrefix(name, identifierPrefix+"-") {
				continue
			}
			p.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"deleting dangling snapshot",
				slog.String("snapshot_uri", *snap.SnapshotId),
			)
			err := p.DeleteSnapshot(ctx, *snap.SnapshotId)
			if err != nil {
				return fmt.Errorf("deleting snapshot %s: %w", *snap.SnapshotId, err)
			}
		}
	}

	vIter := ec2.NewDescribeVolumesPaginator(p.ec2, &ec2.DescribeVolumesInput{})
	for vIter.HasMorePages() {
		page, err := vIter.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("request next volumes page: %w", err)
		}
		for _, vol := range page.Volumes {
			name := resourceNameFromTags(vol.Tags)
			if !strings.HasPrefix(name, identifierPrefix+"-") {
				continue
			}
			p.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"deleting dangling disk",
				slog.String("disk_uri", *vol.VolumeId),
			)
			err := p.DeleteDisk(ctx, *vol.VolumeId)
			if err != nil {
				return fmt.Errorf("deleting volume %s: %w", *vol.VolumeId, err)
			}
		}
	}

	return nil
}
