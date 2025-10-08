package orchestrator

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/accuknox/omniscan/api/v1alpha1"
	kubeUtil "github.com/accuknox/omniscan/pkg/job/kube/util"
	"github.com/accuknox/omniscan/pkg/provider"
)

type Job struct {
	opts
	scanName      string
	scanNamespace string
	prov          provider.Provider
}

func New(scanName, scanNamespace string, prov provider.Provider, fns ...OptFunc) Job {
	o := defaultOpts()
	for _, fn := range fns {
		fn(&o)
	}
	return Job{
		opts:          o,
		scanName:      scanName,
		scanNamespace: scanNamespace,
		prov:          prov,
	}
}

func (j Job) Run(ctx context.Context) error {
	kubeClient, err := kubeUtil.NewKubeClient()
	if err != nil {
		return fmt.Errorf("creating kube client: %w", err)
	}

	omniClient, err := kubeUtil.NewOmniClient()
	if err != nil {
		return fmt.Errorf("creating omni client: %w", err)
	}

	scan, err := omniClient.ApiV1alpha1().Scans(j.scanNamespace).Get(ctx, j.scanName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("GET Scan %s: %w", j.scanName, err)
	}

	vmURI := scan.Namespace + "/" + scan.Spec.VirtualMachineName
	hash, err := scan.Hash()
	if err != nil {
		return fmt.Errorf("calculating hash of Scan spec")
	}
	jobName := scan.Name + "-orch-" + hash
	if len(jobName) > 63 {
		jobName = jobName[:63]
	}

	j.logger.LogAttrs(ctx, slog.LevelInfo, "initializing provider")
	if err := j.prov.Init(ctx); err != nil {
		return fmt.Errorf("initialization given provider: %w", err)
	}

	disks, err := j.prov.ListVMDisks(ctx, vmURI)
	if err != nil {
		return fmt.Errorf("listing vm %s disks: %w", vmURI, err)
	}

	if len(disks) == 0 {
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"no disks attached to the target VM. Skipping...",
			slog.String("target_vm_uri", vmURI),
		)
		return nil
	}
	disk := disks[0]

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"creating snapshot of source disk",
		slog.String("source_disk_uri", disk.URI),
	)
	snap, err := j.prov.CreateSnapshot(ctx, disk.URI)
	if err != nil {
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
			Type:    v1alpha1.ScanConditionSnapshotTaken,
			Status:  corev1.ConditionFalse,
			Reason:  "SnapshotCreationFailed",
			Message: err.Error(),
		})
		j.prov.DeleteSnapshot(ctx, snap)
		return fmt.Errorf("creating snapshot of disk %q: %w", disk.URI, err)
	}

	if err := addSnapshotAnnotation(ctx, jobName, snap, kubeClient); err != nil {
		return fmt.Errorf("adding snapshot annotation to myself: %w", err)
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"waiting for snapshot to be ready",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", disk.URI),
	)
	err = j.prov.WaitSnapshotReady(ctx, snap)
	if err != nil {
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
			Type:    v1alpha1.ScanConditionSnapshotTaken,
			Status:  corev1.ConditionFalse,
			Reason:  "SnapshotWaitFailed",
			Message: err.Error(),
		})
		j.prov.DeleteSnapshot(ctx, snap)
		return fmt.Errorf("waiting for snapshot %q: %w", snap, err)
	}

	kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionSnapshotTaken,
		Status:  corev1.ConditionTrue,
		Reason:  "SnapshotCreated",
		Message: "volume snapshot created",
	})

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"creating disk from the snapshot",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", disk.URI),
	)
	clone, err := j.prov.ConvertSnapshot2Disk(ctx, snap)
	if err != nil {
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
			Type:    v1alpha1.ScanConditionClonedPVCReady,
			Status:  corev1.ConditionFalse,
			Reason:  "CreatePVCFromSnapshotFailed",
			Message: err.Error(),
		})
		j.prov.DeleteDisk(ctx, clone)
		j.prov.DeleteSnapshot(ctx, snap)
		return fmt.Errorf("converting snapshot %q to disk: %w", snap, err)
	}

	if err := addDiskAnnotation(ctx, jobName, clone, kubeClient); err != nil {
		return fmt.Errorf("adding cloned pvc annotation to myself: %w", err)
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"waiting for cloned disk to be ready",
		slog.String("snapshot_uri", snap),
		slog.String("source_disk_uri", disk.URI),
		slog.String("cloned_disk_uri", clone),
	)
	err = j.prov.WaitDiskReady(ctx, clone)
	if err != nil {
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
			Type:    v1alpha1.ScanConditionClonedPVCReady,
			Status:  corev1.ConditionFalse,
			Reason:  "ClonedPVCWaitFailed",
			Message: err.Error(),
		})
		j.prov.DeleteDisk(ctx, clone)
		j.prov.DeleteSnapshot(ctx, snap)
		return fmt.Errorf("waiting for cloned disk %q: %w", clone, err)
	}

	kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionClonedPVCReady,
		Status:  corev1.ConditionTrue,
		Reason:  "CreatedPVCFromSnapshot",
		Message: "PVC created from volume snapshot",
	})

	return nil
}
