package openshift

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/accuknox/omniscan/pkg/resource"
	"github.com/accuknox/omniscan/pkg/util"
)

func (p Provider) AttachDisk(ctx context.Context, diskURI, vmURI string) (string, error) {
	return "", nil
}

func (p Provider) DetachDisk(ctx context.Context, diskURI, vmURI string) error {
	return nil
}

func (p Provider) DeleteDisk(ctx context.Context, diskURI string) error {
	name, namespace := util.SplitKubernetesNamespaced(diskURI)
	return p.kubeClient.
		CoreV1().
		PersistentVolumeClaims(namespace).
		Delete(ctx, name, metav1.DeleteOptions{})
}

func (p Provider) ListDisks(ctx context.Context) ([]resource.Disk, error) {
	var (
		cntinue string
		disks   []resource.Disk
	)
	for {
		lst, err := p.kubeClient.
			CoreV1().
			PersistentVolumeClaims(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{
				Limit:    30,
				Continue: cntinue,
			})
		if err != nil {
			return nil, fmt.Errorf("fetching PVCs from apisrv: %w", err)
		}
		cntinue = lst.GetContinue()
		if cntinue == "" {
			break
		}
		for _, pvc := range lst.Items {
			if !p.nsFilter(pvc.Name) {
				continue
			}
			disks = append(disks, resource.Disk{
				URI: pvc.Namespace + "/" + pvc.Name,
			})
		}
	}
	return disks, nil
}

func (p Provider) ListVMDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	vmName, namespace := util.SplitKubernetesNamespaced(vmURI)
	vm, err := p.virtClient.
		KubevirtV1().
		VirtualMachines(namespace).
		Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("fetching vm %s from apisrv: %w", vmURI, err)
	}
	bootDisk := findBootDisk(vm.Spec.Template.Spec.Domain.Devices.Disks)
	if bootDisk == nil {
		return nil, fmt.Errorf("boot disk not found")
	}
	for _, vol := range vm.Spec.Template.Spec.Volumes {
		if vol.Name != bootDisk.Name {
			continue
		}
		var uri string
		switch {
		case vol.PersistentVolumeClaim != nil:
			uri = vm.Namespace + "/" + vol.PersistentVolumeClaim.ClaimName
		case vol.Ephemeral != nil:
			uri = vm.Namespace + "/" + vol.Ephemeral.PersistentVolumeClaim.ClaimName
		case vol.DataVolume != nil:
			uri = vm.Namespace + "/" + vol.DataVolume.Name
		}
		if uri == "" {
			return nil, fmt.Errorf("unsupported boot disk")
		}
		return []resource.Disk{
			{URI: uri},
		}, nil
	}
	return nil, fmt.Errorf("boot disk volume not found")
}

func (p Provider) ListVMUnattachedDisks(ctx context.Context, vmURI string) ([]resource.Disk, error) {
	return nil, nil
}

func (p Provider) ListUnattachedDisks(ctx context.Context) ([]resource.Disk, error) {
	return nil, nil
}

func (p Provider) WaitDiskReady(ctx context.Context, diskURI string) error {
	pvcName, namespace := util.SplitKubernetesNamespaced(diskURI)
	return wait.PollUntilContextTimeout(
		ctx,
		time.Second*5,
		p.waitReadyTimeout,
		true,
		func(ctx context.Context) (done bool, err error) {
			pvc, err := p.kubeClient.
				CoreV1().
				PersistentVolumeClaims(namespace).
				Get(ctx, pvcName, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("fetching pvc %s from apisrv: %w", diskURI, err)
			}
			if pvc.Status.Phase == corev1.ClaimLost {
				return false, fmt.Errorf("claim lost")
			}
			return pvc.Status.Phase == corev1.ClaimBound || pvc.Status.Phase == corev1.ClaimPending, nil
		},
	)
}
