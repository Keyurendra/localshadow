package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	flanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func (s *s) scanOne(ctx context.Context, imageRef, runtime, runtimeHost string, namespaces []string, vmURI, platform, osType string) (scanner.Findings, error) {
	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  s.timeout,
			CacheDir: s.cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: "fs",
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          []types.Scanner{types.VulnerabilityScanner},
			DisableTelemetry:  true,
			Target:            imageRef,
			DetectionPriority: flanalTypes.PriorityPrecise,
			Parallel:          0,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbTypes.SourceID{"auto"},
		},
		DBOptions: flag.DBOptions{
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{"os"},
			PkgRelationships: []flanalTypes.Relationship{
				flanalTypes.RelationshipUnknown,
				flanalTypes.RelationshipRoot,
				flanalTypes.RelationshipWorkspace,
				flanalTypes.RelationshipDirect,
				flanalTypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      types.FormatJSON,
			ListAllPkgs: false,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
		ImageOptions: flag.ImageOptions{
			ImageSources: flanalTypes.AllImageSources,
		},
	}

	restore := setCtrdEnv(runtime, runtimeHost)
	defer restore()

	report, err := s.scanLocal(ctx, opts, runtime, namespaces)
	if err != nil && s.remoteFallback && retryRemote(runtime, err) {
		slog.WarnContext(
			ctx,
			"retrying scan with remote image source",
			slog.String("image", imageRef),
			slog.String("runtime", runtime),
		)
		opts.ImageSources = []flanalTypes.ImageSource{flanalTypes.RemoteImageSource}
		report, err = s.scanReport(ctx, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("scanning rootfs %s: %w", imageRef, err)
	}

	return &trivy.Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "container_image",
		Results:       report.Results,
		Metadata: trivy.Metadata{
			Size:        report.Metadata.Size,
			OS:          report.Metadata.OS,
			ImageID:     report.Metadata.ImageID,
			DiffIDs:     report.Metadata.DiffIDs,
			RepoTags:    report.Metadata.RepoTags,
			RepoDigests: report.Metadata.RepoDigests,
			ImageConfig: report.Metadata.ImageConfig,
			Layers:      report.Metadata.Layers,
			VM: trivy.VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
	}, nil
}

// scanLocal enforces namespace-based lookup for containerd to avoid
// ambiguous implicit defaults that vary by host/runtime setup.
func (s *s) scanLocal(ctx context.Context, opts flag.Options, runtime string, namespaces []string) (*types.Report, error) {
	if runtime != "containerd" {
		return s.scanReport(ctx, opts)
	}
	if len(namespaces) == 0 {
		return nil, errors.New("containerd namespaces list is empty")
	}
	return s.scanNS(ctx, opts, namespaces)
}

// scanNS iterates namespace candidates to find the image in local
// containerd stores before falling back to remote sources.
func (s *s) scanNS(ctx context.Context, opts flag.Options, namespaces []string) (*types.Report, error) {
	ns := uniqNS(namespaces)
	if len(ns) == 0 {
		return nil, errors.New("containerd namespaces list is empty")
	}

	var scanErr error
	for _, n := range ns {
		restore := setCtrdNS(n)
		report, err := s.scanReport(ctx, opts)
		restore()
		if err == nil {
			return report, nil
		}
		scanErr = errors.Join(scanErr, fmt.Errorf("namespace %q: %w", n, err))
	}
	return nil, scanErr
}

func (s *s) scanReport(ctx context.Context, opts flag.Options) (*types.Report, error) {
	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetContainerImage)
	if err != nil {
		return nil, fmt.Errorf("initializing scanner: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanImage(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &report, nil
}
