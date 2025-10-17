package util

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/publisher/cspm"
	"github.com/accuknox/omniscan/pkg/util"
)

var rootfs string

func init() {
	rootfs, _ = util.FindRootFS()
}

func CloudScanCmdFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally only",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to local publisher's store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox",
		},
		&cli.StringFlag{
			Name:  "artifact-endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com/api/v1/artifact/",
		},
		&cli.UintFlag{
			Name:        "tenant-id",
			Usage:       "AccuKnox tenant ID",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:  "artifact-label",
			Usage: "Label to associate with the artifact",
		},
		&cli.StringFlag{
			Name:      "artifact-token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "skip-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
		&cli.StringFlag{
			Name:      "vuln-db-directory",
			Usage:     "Path to vulnerability scanner's database directory",
			Value:     "/root/.cache/trivy/",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "vm-name-regex",
			Usage: "Filter VMs by name using regex",
		},
		&cli.StringMapFlag{
			Name:  "vm-label-regex",
			Usage: "Filter VMs by label using regex",
		},
		&cli.UintFlag{
			Name:  "concurrency",
			Usage: "Number of concurrent scans",
			Value: uint(runtime.NumCPU()),
		},
	}
}

func CloudScheduleCmdFlags() []cli.Flag {
	return append([]cli.Flag{
		&cli.StringFlag{
			Name:  "crontab",
			Value: "@daily",
			Usage: "Cron expression for scheduling",
		},
		&cli.BoolFlag{
			Name:  "trigger-immediately",
			Value: false,
			Usage: "Trigger the first scan right after scheduling",
		},
		&cli.BoolFlag{
			Name:  "enable-prometheus-metrics",
			Value: false,
			Usage: "Enable prometheus metrics endpoint",
		},
		&cli.Uint16Flag{
			Name:  "prometheus-metrics-port",
			Value: 9100,
			Usage: "Port for prometheus metrics",
		},
	}, CloudScanCmdFlags()...)
}

func AgentScanCmdFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally only",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to local publisher's store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox",
		},
		&cli.StringFlag{
			Name:  "artifact-endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com/api/v1/artifact/",
		},
		&cli.UintFlag{
			Name:        "tenant-id",
			Usage:       "AccuKnox tenant ID",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:  "artifact-label",
			Usage: "Label to associate with the artifact",
		},
		&cli.StringFlag{
			Name:      "artifact-token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "skip-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
		&cli.StringFlag{
			Name:      "vuln-db-directory",
			Usage:     "Path to vulnerability scanner's database directory",
			Value:     "/var/lib/accuknox-omni/",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:      "malware-scan-target-directory",
			Usage:     "Limit malware scan to a specific directory",
			Value:     rootfs,
			TakesFile: true,
		},
	}
}

func AgentScheduleCmdFlags() []cli.Flag {
	return append([]cli.Flag{
		&cli.StringFlag{
			Name:  "crontab",
			Value: "@daily",
			Usage: "Cron expression for scheduling",
		},
		&cli.BoolFlag{
			Name:  "trigger-immediately",
			Value: false,
			Usage: "Trigger the first scan right after scheduling",
		},
	}, AgentScanCmdFlags()...)
}

func CreateCSPMPublisher(c *cli.Command) (publisher.Publisher, error) {
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
