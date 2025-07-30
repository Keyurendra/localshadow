package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/accuknox/omniscan/internal/artifact"

	"github.com/urfave/cli/v3"
)

func cspmPubisher(c *cli.Command) (artifact.Publisher, error) {
	endpoint := c.String("endpoint")
	if endpoint == "" {
		return nil, fmt.Errorf("missing `--endpoint`")
	}

	tenantID := c.Uint("tenant-id")
	if tenantID == 0 {
		return nil, fmt.Errorf("missing `--tenant-id`")
	}

	label := c.String("label")
	if label == "" {
		return nil, fmt.Errorf("missing `--label`")
	}

	tokenFile := c.String("token-file")
	if tokenFile == "" {
		return nil, fmt.Errorf("missing `--token-file`")
	}

	tkn, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file %q: %w", tokenFile, err)
	}

	return artifact.NewCSPMPublisher(artifact.CSPMPublisherConfig{
		Endpoint: endpoint,
		TenantID: tenantID,
		LabelID:  label,
		Token:    strings.TrimSpace(string(tkn)),
	})
}
