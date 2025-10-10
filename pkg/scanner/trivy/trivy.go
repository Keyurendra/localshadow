package trivy

import (
	"context"
	"fmt"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	flanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner"
)

type s struct {
	opts
}

func NewScanner(fns ...OptFunc) (scanner.Scanner, error) {
	o, err := defaultOpts()
	if err != nil {
		return nil, fmt.Errorf("initializing opts: %w", err)
	}
	for _, fn := range fns {
		fn(o)
	}
	return &s{
		opts: *o,
	}, nil
}

func (s s) Scan(ctx context.Context, mountpoint, vmURI, platform, osType string) (scanner.Findings, error) {
	opts := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  s.timeout,
			CacheDir: s.cacheDir,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: "memory",
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          []types.Scanner{types.VulnerabilityScanner},
			DisableTelemetry:  true,
			Target:            mountpoint,
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
			ListAllPkgs: true,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
	}

	runner, err := artifact.NewRunner(ctx, opts, artifact.TargetRootfs)
	if err != nil {
		return nil, fmt.Errorf("initializing scanner: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanRootfs(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("scanning rootfs %s: %w", mountpoint, err)
	}

	return &Result{
		SchemaVersion: report.SchemaVersion,
		CreatedAt:     report.CreatedAt,
		ArtifactName:  report.ArtifactName,
		ArtifactType:  "rootfs",
		Results:       report.Results,
		Metadata: Metadata{
			Size:        report.Metadata.Size,
			OS:          report.Metadata.OS,
			ImageID:     report.Metadata.ImageID,
			DiffIDs:     report.Metadata.DiffIDs,
			RepoTags:    report.Metadata.RepoTags,
			RepoDigests: report.Metadata.RepoDigests,
			ImageConfig: report.Metadata.ImageConfig,
			Layers:      report.Metadata.Layers,
			VM: VMMetadata{
				URI:      vmURI,
				Platform: platform,
				OS:       osType,
			},
		},
	}, nil
}
