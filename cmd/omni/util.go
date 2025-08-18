package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/publisher/cspm"

	"github.com/urfave/cli/v3"
)

func cspmPubisher(c *cli.Command) (publisher.Publisher, error) {
	endpoint := c.String("artifact-endpoint")
	if endpoint == "" {
		return nil, fmt.Errorf("missing `--artifact-endpoint`")
	}

	tenantID := c.Uint("tenant-id")
	if tenantID == 0 {
		return nil, fmt.Errorf("missing `--tenant-id`")
	}

	label := c.String("artifact-label")
	if label == "" {
		return nil, fmt.Errorf("missing `--artifact-label`")
	}

	tokenFile := c.String("artifact-token-file")
	if tokenFile == "" {
		return nil, fmt.Errorf("missing `--artifact-token-file`")
	}

	tkn, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file %q: %w", tokenFile, err)
	}

	return cspm.NewPublisher(cspm.Config{
		Endpoint: endpoint,
		TenantID: tenantID,
		LabelID:  label,
		Token:    strings.TrimSpace(string(tkn)),
	}, nil)
}
