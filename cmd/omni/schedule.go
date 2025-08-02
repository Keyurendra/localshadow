package main

import (
	"context"
	"fmt"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/job"
	"github.com/accuknox/omniscan/internal/provider/gcp"
	"github.com/accuknox/omniscan/internal/provider/retry"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/resource"

	"github.com/urfave/cli/v3"
)

var scheduleCmd = &cli.Command{
	Name:      "schedule",
	Arguments: scanCmd.Arguments,
	Flags: append(scanCmd.Flags, []cli.Flag{
		&cli.StringFlag{
			Name:  "crontab",
			Value: "@daily",
			Usage: "CronJob schedule",
		},
	}...),
	Action: func(ctx context.Context, c *cli.Command) error {
		var provider provider.Provider
		var err error
		arg := c.StringArg("provider")

		switch arg {
		case "gcp":
			provider, err = gcp.NewProvider(&resource.Filter{
				Name:   c.String("vm-name-filter"),
				Labels: c.StringMap("vm-label-filter"),
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

		opts := []job.OptFunc{job.WithConcurrency(c.Uint("concurrency"))}
		if c.Bool("skip-malware-scan") {
			opts = append(opts, job.WithClamscanDisabled())
		}

		j := job.NewScanJob(provider, publisher, opts...)
		return j.Schedule(ctx, c.String("crontab"), true)
	},
}
