package util

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Keyurendra/shadowtest/api/v1alpha1"
	omniClientset "github.com/Keyurendra/shadowtest/pkg/generated/clientset/versioned"
)

// JobName keeps workload and RBAC resource names within the DNS label limit.
func JobName(scanName, typ, hash string) string {
	name := scanName + "-" + typ + "-" + hash
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimSuffix(name, "-")
}

func NewOmniClient() (omniClientset.Interface, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("creating kube config: %w", err)
	}
	return omniClientset.NewForConfig(cfg)
}

func NewKubeClient() (kubernetes.Interface, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("creating kube config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

func UpdateScanCondition(ctx context.Context, scanName, scanNamespace string, cond v1alpha1.ScanCondition) (*v1alpha1.Scan, error) {
	c, err := NewOmniClient()
	if err != nil {
		return nil, fmt.Errorf("creating omni client: %w", err)
	}
	obj := c.ApiV1alpha1().Scans(scanNamespace)
	scan, err := obj.Get(ctx, scanName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("GET Scan %s: %w", scanName, err)
	}
	scan.Status.SetCondition(cond)
	return obj.UpdateStatus(ctx, scan, metav1.UpdateOptions{})
}
