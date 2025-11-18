package openshift

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/accuknox/omniscan/pkg/resource"
)

func (p Provider) ListVMs(ctx context.Context) ([]resource.VM, error) {
	var (
		cntinue, labelSelector string
		vms                    []resource.VM
	)
	if p.labelsSelector != nil {
		labelSelector = p.labelsSelector.String()
	}
	for {
		lst, err := p.virtClient.
			KubevirtV1().
			VirtualMachines(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
				Limit:         30,
				Continue:      cntinue,
			})
		if err != nil {
			return nil, fmt.Errorf("fetching vms from the apisrv: %w", err)
		}
		for _, vm := range lst.Items {
			vmURI := vm.Namespace + "/" + vm.Name
			if !vm.Status.Ready || !p.nsFilter(vm.Namespace) {
				continue
			}
			bootDisk := findBootDisk(vm.Spec.Template.Spec.Domain.Devices.Disks)
			for _, vol := range vm.Spec.Template.Spec.Volumes {
				if bootDisk != nil && vol.Name != bootDisk.Name {
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
					p.logger.LogAttrs(
						ctx,
						slog.LevelInfo,
						"unsupported boot disk",
						slog.String("vm_uri", vmURI),
					)
					continue
				}
				vms = append(vms, resource.VM{
					URI: vmURI,
					Disks: []resource.Disk{
						{URI: uri},
					},
				})
			}
		}
		cntinue = lst.GetContinue()
		if cntinue == "" {
			break
		}
	}
	return vms, nil
}

func (p Provider) GetCurrentVM(ctx context.Context) (*resource.VM, error) {
	return nil, nil
}
