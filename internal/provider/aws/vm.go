package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/accuknox/omniscan/pkg/provider/resource"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (p *Provider) ListVMs(ctx context.Context) ([]resource.VM, error) {
	iter := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{})

	var vms []resource.VM

	for iter.HasMorePages() {
		page, err := iter.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("querying next page: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, i := range reservation.Instances {
				if i.State == nil || i.State.Name != types.InstanceStateNameRunning {
					continue
				}

				if i.InstanceId == nil {
					continue
				}
				instanceID := *i.InstanceId

				name := resourceNameFromTags(i.Tags)
				if r := p.vmFilter.Name; r != nil && !r.MatchString(name) {
					p.logger.LogAttrs(
						ctx,
						slog.LevelDebug,
						"instance name did not match the provided filter. Skipping...",
						slog.String("vm_uri", instanceID),
						slog.String("vm_name", name),
					)
					continue
				}

				var match bool

			NextLabel:
				for _, t := range i.Tags {
					var k, v string
					if t.Key != nil {
						k = *t.Key
					}
					if t.Value != nil {
						v = *t.Value
					}
					if k == "" && v == "" {
						continue
					}
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
						slog.String("vm_uri", instanceID),
						slog.Any("vm_labels", i.Tags),
					)
					continue
				}

				volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
					Filters: []types.Filter{
						{
							Name:   aws.String("attachment.instance-id"),
							Values: []string{instanceID},
						},
					},
				})
				if err != nil {
					return nil, fmt.Errorf("listing volumes attached to %q: %w", instanceID, err)
				}

				var disks []resource.Disk

				for _, vol := range volumes.Volumes {
					if vol.State != types.VolumeStateInUse {
						continue
					}
					disks = append(disks, resource.Disk{
						URI: *vol.VolumeId,
					})
				}

				vms = append(vms, resource.VM{
					URI:   instanceID,
					Disks: disks,
				})
			}
		}
	}

	return vms, nil
}

func (p *Provider) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	host, err := p.imds.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return nil, fmt.Errorf("querying host instance identity: %w", err)
	}

	volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{host.InstanceID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("querying volumes attached to host: %w", err)
	}

	var disks []resource.Disk
	for _, vol := range volumes.Volumes {
		if vol.State == types.VolumeStateInUse {
			disks = append(disks, resource.Disk{
				URI: *vol.VolumeId,
			})
		}
	}

	return &resource.VM{
		URI:   host.InstanceID,
		Disks: disks,
	}, nil
}
