package openshift

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	volumesnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/Keyurendra/shadowtest/pkg/resource"
	"github.com/Keyurendra/shadowtest/pkg/util"
)

func (p Provider) ListSnapshots(ctx context.Context) ([]resource.Snapshot, error) {
	var (
		snapshots []resource.Snapshot
		cntinue   string
	)
	for {
		snaps, err := p.snapshotClient.
			SnapshotV1().
			VolumeSnapshots(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{
				Limit:    30,
				Continue: cntinue,
			})
		if err != nil {
			return nil, fmt.Errorf("listing snapshots: %w", err)
		}
		cntinue = snaps.GetContinue()
		if cntinue == "" {
			break
		}
		for _, snap := range snaps.Items {
			if !p.nsFilter(snap.Namespace) {
				continue
			}
			snapshots = append(snapshots, resource.Snapshot{
				URI: snap.Namespace + "/" + snap.Name,
			})
		}
	}
	return snapshots, nil
}

func (p Provider) CreateSnapshot(ctx context.Context, diskURI string) (string, error) {
	pvcName, namepace := util.SplitKubernetesNamespaced(diskURI)
	name := p.scanName + "-" + uuid.NewString()
	snap, err := p.snapshotClient.
		SnapshotV1().
		VolumeSnapshots(namepace).
		Create(
			ctx,
			&volumesnapshotv1.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:            name,
					Namespace:       namepace,
					OwnerReferences: []metav1.OwnerReference{p.ownerRef},
				},
				Spec: volumesnapshotv1.VolumeSnapshotSpec{
					VolumeSnapshotClassName: p.volumeSnapshotClassName,
					Source: volumesnapshotv1.VolumeSnapshotSource{
						PersistentVolumeClaimName: &pvcName,
					},
				},
			},
			metav1.CreateOptions{},
		)
	if err != nil {
		return "", err
	}
	return snap.Namespace + "/" + snap.Name, nil
}

func (p Provider) WaitSnapshotReady(ctx context.Context, snapshotURI string) error {
	snapName, namespace := util.SplitKubernetesNamespaced(snapshotURI)
	return wait.PollUntilContextTimeout(
		ctx,
		time.Second*5,
		p.waitReadyTimeout,
		true,
		func(ctx context.Context) (done bool, err error) {
			snap, err := p.snapshotClient.
				SnapshotV1().
				VolumeSnapshots(namespace).
				Get(ctx, snapName, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("fetching snapshot %s: %w", snapshotURI, err)
			}
			if snap.Status == nil {
				return false, nil
			}
			if snap.Status.Error != nil && snap.Status.Error.Message != nil {
				return false, fmt.Errorf("creating snapshot: %s", *snap.Status.Error.Message)
			}
			if snap.Status.ReadyToUse == nil {
				return false, nil
			}
			return *snap.Status.ReadyToUse, nil
		},
	)
}

func (p Provider) ConvertSnapshot2Disk(ctx context.Context, snapshotURI string) (string, error) {
	snapName, namespace := util.SplitKubernetesNamespaced(snapshotURI)
	snap, err := p.snapshotClient.
		SnapshotV1().
		VolumeSnapshots(namespace).
		Get(ctx, snapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("fetching snapshot %s: %w", snapshotURI, err)
	}

	srcPvcName := snap.Spec.Source.PersistentVolumeClaimName
	if srcPvcName == nil {
		return "", fmt.Errorf("snapshot source is missing")
	}
	srcPvc, err := p.kubeClient.
		CoreV1().
		PersistentVolumeClaims(namespace).
		Get(ctx, *srcPvcName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("fetching pvc %s/%s: %w", namespace, *srcPvcName, err)
	}

	if snap.Status == nil || snap.Status.RestoreSize == nil {
		return "", fmt.Errorf("restoreSize missing in snapshot status")
	}

	clonedPvcName := p.scanName + "-" + uuid.NewString()
	clonedPvc, err := p.kubeClient.
		CoreV1().
		PersistentVolumeClaims(namespace).
		Create(
			ctx,
			&corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:            clonedPvcName,
					Namespace:       namespace,
					OwnerReferences: []metav1.OwnerReference{p.ownerRef},
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					DataSource: &corev1.TypedLocalObjectReference{
						APIGroup: util.Ptr("snapshot.storage.k8s.io"),
						Kind:     "VolumeSnapshot",
						Name:     snapName,
					},
					StorageClassName: srcPvc.Spec.StorageClassName,
					VolumeMode:       util.Ptr(corev1.PersistentVolumeBlock),
					AccessModes:      srcPvc.Spec.AccessModes,
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: *snap.Status.RestoreSize,
						},
					},
				},
			}, metav1.CreateOptions{},
		)
	if err != nil {
		return "", fmt.Errorf("creating clone pvc: %w", err)
	}

	return clonedPvc.Namespace + "/" + clonedPvc.Name, nil
}

func (p Provider) DeleteSnapshot(ctx context.Context, snapshotURI string) error {
	snapName, namespace := util.SplitKubernetesNamespaced(snapshotURI)
	return p.snapshotClient.
		SnapshotV1().
		VolumeSnapshots(namespace).
		Delete(ctx, snapName, metav1.DeleteOptions{})
}
