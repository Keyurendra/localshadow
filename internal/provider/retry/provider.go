package retry

import (
	"context"

	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/provider/resource"

	"github.com/avast/retry-go/v4"
)

type Retry struct {
	p provider.Provider
	opts
}

func NewProvider(p provider.Provider, optFns ...OptFunc) provider.Provider {
	o := defaultOpts()
	for _, f := range optFns {
		f(&o)
	}
	return Retry{
		p:    p,
		opts: o,
	}
}

func (r Retry) GetName() string {
	return r.p.GetName()
}

func (r Retry) Init(ctx context.Context) error {
	return retry.Do(func() error {
		return r.p.Init(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) PruneDangling(ctx context.Context) error {
	return retry.Do(func() error {
		return r.p.PruneDangling(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListVMs(ctx context.Context) ([]resource.VM, error) {
	return retry.DoWithData(func() ([]resource.VM, error) {
		return r.p.ListVMs(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	return retry.DoWithData(func() (*resource.VM, error) {
		return r.p.GetCurrentVM(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) AttachDisk(ctx context.Context, diskURI, vmURI string) (string, error) {
	return retry.DoWithData(func() (string, error) {
		return r.p.AttachDisk(ctx, diskURI, vmURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) DetachDisk(ctx context.Context, diskURI, vmURI string) error {
	return retry.Do(func() error {
		return r.p.DetachDisk(ctx, diskURI, vmURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) DeleteDisk(ctx context.Context, diskURI string) error {
	return retry.Do(func() error {
		return r.p.DeleteDisk(ctx, diskURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListDisks(ctx context.Context) ([]resource.Disk, error) {
	return retry.DoWithData(func() ([]resource.Disk, error) {
		return r.p.ListDisks(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	return retry.DoWithData(func() ([]resource.Disk, error) {
		return r.p.ListVMDisks(ctx, vmURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	return retry.DoWithData(func() ([]resource.Disk, error) {
		return r.p.ListVMUnattachedDisks(ctx, vmURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) {
	return retry.DoWithData(func() ([]resource.Disk, error) {
		return r.p.ListUnattachedDisks(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) WaitDiskReady(ctx context.Context, diskURI string) error {
	return retry.Do(func() error {
		return r.p.WaitDiskReady(ctx, diskURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) {
	return retry.DoWithData(func() ([]resource.Snapshot, error) {
		return r.p.ListSnapshots(ctx)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) CreateSnapshot(ctx context.Context, diskURI string) (string, error) {
	return retry.DoWithData(func() (string, error) {
		return r.p.CreateSnapshot(ctx, diskURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) WaitSnapshotReady(ctx context.Context, snapshotURI string) error {
	return retry.Do(func() error {
		return r.p.WaitSnapshotReady(ctx, snapshotURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error) {
	return retry.DoWithData(func() (string, error) {
		return r.p.ConvertSnapshot2Disk(ctx, snapshotURI)
	}, r.getRetryOpts(ctx)...)
}

func (r Retry) DeleteSnapshot(ctx context.Context, snapshotURI string) error {
	return retry.Do(func() error {
		return r.p.DeleteSnapshot(ctx, snapshotURI)
	}, r.getRetryOpts(ctx)...)
}
