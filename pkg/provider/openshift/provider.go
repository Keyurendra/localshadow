package openshift

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	snapshotClientset "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"kubevirt.io/client-go/kubevirt"
	ctrl "sigs.k8s.io/controller-runtime"

	omniClientset "github.com/accuknox/omniscan/pkg/generated/clientset/versioned"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/util"
)

type Provider struct {
	opts
	scanName       string
	scanNamespace  string
	kubeClient     kubernetes.Interface
	virtClient     kubevirt.Interface
	snapshotClient snapshotClientset.Interface
	omniClient     omniClientset.Interface
	ownerRef       metav1.OwnerReference
}

func NewProvider(scanName, scanNamespace string, fns ...OptFunc) (provider.Provider, error) {
	o := defaultOpts()
	for _, f := range fns {
		err := f(&o)
		if err != nil {
			return nil, err
		}
	}
	return &Provider{
		opts:          o,
		scanName:      scanName,
		scanNamespace: scanNamespace,
	}, nil
}

func (p Provider) GetName() string {
	return "openshift"
}

func (p *Provider) Init(ctx context.Context) error {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("creating kube config: %w", err)
	}

	p.kubeClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	p.virtClient, err = kubevirt.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating kubevirt client: %w", err)
	}

	p.snapshotClient, err = snapshotClientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating snapshot client: %w", err)
	}

	p.omniClient, err = omniClientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating omni client: %w", err)
	}

	if p.scanName != "" {
		scan, err := p.omniClient.ApiV1alpha1().Scans(p.scanNamespace).Get(
			ctx,
			p.scanName,
			metav1.GetOptions{},
		)
		if err != nil {
			return fmt.Errorf("GET Scan %s: %w", p.scanName, err)
		}

		p.ownerRef = metav1.OwnerReference{
			APIVersion: "omni.accuknox.com/v1alpha1",
			Kind:       "Scan",
			Name:       scan.Name,
			UID:        scan.UID,
			Controller: util.Ptr(true),
		}
	}

	return nil
}

func (p Provider) PruneDangling(ctx context.Context) error {
	snaps, err := p.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("listing snapshots: %w", err)
	}
	for _, s := range snaps {
		snapName, _ := util.SplitKubernetesNamespaced(s.URI)
		if !strings.HasPrefix(snapName, p.scanName+"-") {
			continue
		}
		p.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"deleting dangling snapshot",
			slog.String("snapshot_uri", s.URI),
		)
		err := p.DeleteSnapshot(ctx, s.URI)
		if err != nil {
			return fmt.Errorf("deleting snapshot %q: %w", s.URI, err)
		}
	}
	// TODO: identify and prune other dangling resources
	return nil
}
