package provider

import (
	"context"

	"github.com/accuknox/omniscan/pkg/resource"
)

type Provider interface {
	Init(ctx context.Context) error
	VM
	Disk
	Snapshot
}

type VM interface {
	ListVMs(ctx context.Context) ([]resource.VM, error) // TODO: return an iterator
	GetCurrentVM(ctx context.Context) (*resource.VM, error)
}

type Disk interface {
	MountDisk(ctx context.Context, diskURI string, vmURI string, devicePath string) error
	UmountDisk(ctx context.Context, diskURI string, vmURI string) error
	DeleteDisk(ctx context.Context, diskURI string) error
	ListDisks(ctx context.Context) ([]resource.Disk, error)           // TODO: return an iterator
	ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) // TODO: return an iterator
	ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error)
	ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error)
	WaitDiskReady(ctx context.Context, diskURI string) error
}

type Snapshot interface {
	ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) // TODO: return an iterator
	CreateSnapshot(ctx context.Context, diskURI string) (string, error)
	WaitSnapshotReady(ctx context.Context, snapshotURI string) error
	ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error)
	DeleteSnapshot(ctx context.Context, snapshotURI string) error
}
