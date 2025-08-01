package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/job"
	"github.com/accuknox/omniscan/internal/provider/gcp"
	"github.com/accuknox/omniscan/internal/provider/retry"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/resource"

	"github.com/urfave/cli/v3"
)

var scanCmd = &cli.Command{
	Name: "scan",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally",
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
			Name:  "vm-name-regex",
			Usage: "filter VMs by name using regex",
		},
		&cli.StringMapFlag{
			Name:  "vm-label-regex",
			Usage: "filter VMs by label using regex",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name:      "provider",
			UsageText: "gcp",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		arg := c.StringArg("provider")
		if arg == "" {
			return fmt.Errorf("missing `provider`")
		}

		var provider provider.Provider
		var err error

		switch arg {
		case "gcp":
			provider, err = gcp.NewProvider(&resource.Filter{
				Name:   c.String("vm-name-regex"),
				Labels: c.StringMap("vm-label-regex"),
			})
		default:
			return fmt.Errorf("unsupported or unknown provider %q", arg)
		}

		if err != nil {
			return fmt.Errorf("setting up %s provider: %w", arg, err)
		}

		provider = retry.NewProvider(provider)

		publisher := artifact.NewFilePublisher(c.String("local-publisher-store-path"))
		if !c.Bool("local-publisher") {
			var err error
			publisher, err = cspmPubisher(c)
			if err != nil {
				return err
			}
		}

		var opts []job.OptFunc
		if c.Bool("skip-malware-scan") {
			opts = append(opts, job.WithClamscanDisabled())
		}

		summary, err := job.NewScanJob(provider, publisher, opts...).Run(ctx)
		if err != nil {
			return fmt.Errorf("executing scan job: %w", err)
		}

		output, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling execution summary to json: %w", err)
		}
		fmt.Println(string(output))

		return nil
	},
}
