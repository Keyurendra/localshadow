package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
)

type s struct{}

func NewScanner() scanner.Scanner {
	return s{}
}

func (s) Scan(ctx context.Context, mountpoint, vmURI, platform string) (scanner.Findings, error) {
	path, err := exec.LookPath("trivy")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("`trivy` executable not found in PATH")
		}
		return nil, fmt.Errorf("looking up trivy in PATH: %w", err)
	}

	var stdout, stderr bytes.Buffer

	cmd := exec.CommandContext(
		ctx,
		path,
		"rootfs",
		mountpoint,
		"--quiet",
		"--format=json",
		"--scanners=vuln",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("executing trivy: %w: %s", err, stderr.String())
	}

	report := new(types.Report)
	if err := json.NewDecoder(&stdout).Decode(report); err != nil {
		return nil, fmt.Errorf("decoding trivy report: %w", err)
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
			},
		},
	}, nil
}
