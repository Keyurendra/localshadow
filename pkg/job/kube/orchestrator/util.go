package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/accuknox/omniscan/pkg/util"
)

func addSnapshotAnnotation(ctx context.Context, jobName, snapURI string, kube kubernetes.Interface) error {
	snapName, namespace := util.SplitKubernetesNamespaced(snapURI)
	patchBytes, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				"omni.accuknox.com/snapshotName": snapName,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshalling patch json: %w", err)
	}
	_, err = kube.BatchV1().Jobs(namespace).Patch(
		ctx,
		jobName,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("patching job: %w", err)
	}
	return nil
}

func addDiskAnnotation(ctx context.Context, jobName, clonedPvcURI string, kube kubernetes.Interface) error {
	pvcName, namespace := util.SplitKubernetesNamespaced(clonedPvcURI)
	patchBytes, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				"omni.accuknox.com/clonedPVCName": pvcName,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshalling patch json: %w", err)
	}
	_, err = kube.BatchV1().Jobs(namespace).Patch(
		ctx,
		jobName,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("patching job: %w", err)
	}
	return nil
}
