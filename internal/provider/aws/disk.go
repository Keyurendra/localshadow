package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider/resource"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awstime "github.com/aws/smithy-go/time"
)

func (p *Provider) AttachDisk(ctx context.Context, diskURI, vmURI string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	usedFSDevices, err := util.ListBlockDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("enumerating currently attached devices: %w", err)
	}

	volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{vmURI},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("querying %s instance's attached volumes: %w", vmURI, err)
	}

	usedAWSDevices := make(map[string]bool)
	isXVD := false

	for _, vol := range volumes.Volumes {
		for _, attachement := range vol.Attachments {
			if attachement.Device != nil {
				usedAWSDevices[*attachement.Device] = true
				if strings.Contains(*attachement.Device, "xvd") {
					isXVD = true
				}
			}
		}
	}

	out, err := p.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{vmURI},
	})
	if err != nil {
		return "", fmt.Errorf("querying instance %s: %w", vmURI, err)
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("could not find instance %s", vmURI)
	}
	instance := out.Reservations[0].Instances[0]

	var devicePath string

	switch instance.VirtualizationType {
	case types.VirtualizationTypeParavirtual:
		for ch := 'f'; ch <= 'p'; ch++ {
			p := "/dev/sd" + string(ch)
			if !usedAWSDevices[p] {
				devicePath = p
				break
			}
		}
	case types.VirtualizationTypeHvm:
		for ch := 'd'; ch <= 'z'; ch++ {
			p := "/dev/sd" + string(ch)
			if isXVD {
				p = "/dev/xvdb" + string(ch)
			}
			if !usedAWSDevices[p] {
				devicePath = p
				break
			}
		}
	}

	_, err = p.ec2.AttachVolume(ctx, &ec2.AttachVolumeInput{
		Device:     aws.String(devicePath),
		InstanceId: instance.InstanceId,
		VolumeId:   aws.String(diskURI),
	})
	if err != nil {
		return "", err
	}

	err = ec2.NewVolumeInUseWaiter(p.ec2).Wait(ctx, &ec2.DescribeVolumesInput{
		VolumeIds: []string{diskURI},
	}, p.waitDeadline)
	if err != nil {
		return "", fmt.Errorf("waiting for volume attachment: %w", err)
	}

	// it takes at most 30s for the disk to appear on the fs
	awstime.SleepWithContext(ctx, time.Second*30)

	newUsedFSDevices, err := util.ListBlockDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("enumerating newly attached devices: %w", err)
	}

	m := make(map[string]struct{})
	for _, dev := range usedFSDevices {
		m[dev] = struct{}{}
	}
	for _, dev := range newUsedFSDevices {
		if _, found := m[dev]; !found {
			return dev, nil
		}
	}

	return "", fmt.Errorf("volume attached but device not found on fs")
}

func (p *Provider) DetachDisk(ctx context.Context, diskURI, vmURI string) error {
	_, err := p.ec2.DetachVolume(ctx, &ec2.DetachVolumeInput{
		VolumeId:   aws.String(diskURI),
		InstanceId: aws.String(vmURI),
	})
	if err != nil {
		return err
	}

	err = ec2.NewVolumeAvailableWaiter(p.ec2).Wait(
		ctx,
		&ec2.DescribeVolumesInput{
			VolumeIds: []string{diskURI},
		},
		p.waitDeadline,
	)
	if err != nil {
		return fmt.Errorf("waiting for volume detachment: %w", err)
	}

	return nil
}

func (p *Provider) DeleteDisk(ctx context.Context, diskURI string) error {
	_, err := p.ec2.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: aws.String(diskURI),
	})
	if err != nil {
		return err
	}

	err = ec2.NewVolumeDeletedWaiter(p.ec2).Wait(
		ctx,
		&ec2.DescribeVolumesInput{
			VolumeIds: []string{diskURI},
		},
		p.waitDeadline,
	)
	if err != nil {
		return fmt.Errorf("waiting for volume deletion: %w", err)
	}

	return nil
}

func (p *Provider) ListDisks(ctx context.Context) ([]resource.Disk, error) {
	var disks []resource.Disk

	iter := ec2.NewDescribeVolumesPaginator(p.ec2, &ec2.DescribeVolumesInput{})
	for iter.HasMorePages() {
		page, err := iter.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("requesting next volume page: %w", err)
		}
		volumes := page.Volumes
		for _, vol := range volumes {
			disks = append(disks, resource.Disk{
				URI: *vol.VolumeId,
			})
		}
	}

	return disks, nil
}

func (p *Provider) ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	volumes, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{vmURI},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	disks := make([]resource.Disk, len(volumes.Volumes))
	for idx, vol := range volumes.Volumes {
		disks[idx] = resource.Disk{
			URI: *vol.VolumeId,
		}
	}

	return disks, nil
}

func (p *Provider) ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	return []resource.Disk{}, nil
}

func (p *Provider) ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) {
	result, err := p.ec2.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing unattached volumes: %w", err)
	}

	var disks []resource.Disk
	for _, volume := range result.Volumes {
		disks = append(disks, resource.Disk{
			URI: *volume.VolumeId,
		})
	}

	return disks, nil
}

func (p *Provider) WaitDiskReady(ctx context.Context, diskURI string) error {
	return ec2.NewVolumeAvailableWaiter(p.ec2).Wait(
		ctx,
		&ec2.DescribeVolumesInput{
			VolumeIds: []string{diskURI},
		},
		p.waitDeadline,
	)
}
