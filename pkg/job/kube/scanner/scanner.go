package scanner

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/accuknox/omniscan/api/v1alpha1"
	"github.com/accuknox/omniscan/pkg/job"
	kubeUtil "github.com/accuknox/omniscan/pkg/job/kube/util"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/util"
)

type Job struct {
	opts
	scanName      string
	scanNamespace string
	prov          provider.Provider
	pub           publisher.Publisher
}

func New(scanName, scanNamespace string, prov provider.Provider, pub publisher.Publisher, fns ...OptFunc) Job {
	o := defaultOpts()
	for _, fn := range fns {
		fn(&o)
	}
	return Job{
		opts:          o,
		scanName:      scanName,
		scanNamespace: scanNamespace,
		prov:          prov,
		pub:           pub,
	}
}

func (j Job) Run(ctx context.Context, mountpoint string) (job.ErrorSummaryMap, error) {
	omniClient, err := kubeUtil.NewOmniClient()
	if err != nil {
		return nil, fmt.Errorf("creating omni client: %w", err)
	}

	scan, err := omniClient.ApiV1alpha1().Scans(j.scanNamespace).Get(ctx, j.scanName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("GET Scan %s: %w", j.scanName, err)
	}
	vmURI := scan.Spec.ClusterName + "://" + scan.Namespace + "/" + scan.Spec.VirtualMachineName

	result, err := j.scanMountPoint(ctx, mountpoint, vmURI)
	if result == nil && err == nil {
		return nil, fmt.Errorf("no partitions qualified for scanning")
	}

	j.logger.LogAttrs(ctx, slog.LevelInfo, "scan complete")

	var errors job.ErrorSummary

	if err != nil {
		errors.OrchestrationError = err
	}

	malwareScanCond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionMalwareScanCompleted,
		Status:  corev1.ConditionTrue,
		Reason:  "ScanSuccessful",
		Message: "scan completed successfully",
	}
	vulnScanCond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionVulnScanCompleted,
		Status:  corev1.ConditionTrue,
		Reason:  "ScanSuccessful",
		Message: "scan completed successfully",
	}
	artifactPublishedCond := v1alpha1.ScanCondition{
		Type:    v1alpha1.ScanConditionArtifactPublished,
		Status:  corev1.ConditionTrue,
		Reason:  "ArtifactPublished",
		Message: "artifact published successfuly",
	}

	if result != nil {
		errors.OS = result.OS

		if result.MalwareScanError != nil {
			malwareScanCond = v1alpha1.ScanCondition{
				Type:    v1alpha1.ScanConditionMalwareScanCompleted,
				Status:  corev1.ConditionFalse,
				Reason:  "ScanFailed",
				Message: result.MalwareScanError.Error(),
			}
			errors.MalwareScanError = result.MalwareScanError
		}

		if result.VulnScanError != nil {
			vulnScanCond = v1alpha1.ScanCondition{
				Type:    v1alpha1.ScanConditionVulnScanCompleted,
				Status:  corev1.ConditionFalse,
				Reason:  "ScanFailed",
				Message: result.VulnScanError.Error(),
			}
			errors.VulnScanError = result.VulnScanError
		}

		err := result.Publish(ctx, j.pub)
		if err != nil {
			artifactPublishedCond = v1alpha1.ScanCondition{
				Type:    v1alpha1.ScanConditionArtifactPublished,
				Status:  corev1.ConditionFalse,
				Reason:  "ArtifactFailedToPublish",
				Message: err.Error(),
			}
			errors.ArtifactAPIError = fmt.Errorf("publishing artifact: %w", err)
		}
	}

	if err == nil {
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, malwareScanCond)
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, vulnScanCond)
		kubeUtil.UpdateScanCondition(ctx, j.scanName, j.scanNamespace, artifactPublishedCond)
	}

	return job.ErrorSummaryMap{vmURI: errors}, nil
}

func (j Job) scanMountPoint(ctx context.Context, mountpoint, vmURI string) (*job.RunResult, error) {
	osType := util.DetectOS(mountpoint)
	if osType == "unknown" {
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"could not determine the OS on mounted partition. Skipping...",
			slog.String("partition_name", mountpoint),
		)
		return nil, nil
	}
	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"OS detected on mounted partition",
		slog.String("partition_name", mountpoint),
		slog.String("os", osType),
	)
	run := job.NewRun(job.RunConfig{
		Logger:                     j.logger,
		VulnScan:                   j.vulnScanEnabled,
		VulnScanDBDir:              j.vulnDBDirectory,
		UseEmbeddedTrivy:           false,
		MalwareScan:                j.malwareScanEnabled,
		MalwareScanTargetDirectory: mountpoint,
		UseClamAVDaemon:            false,
		OfflineWinVulnScan:         true,
	})
	return run.ScanMountPoint(ctx, osType, mountpoint, vmURI, j.prov.GetName())
}
