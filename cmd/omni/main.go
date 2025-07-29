package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/job"
	"github.com/accuknox/omniscan/internal/provider/gcp"
	"github.com/accuknox/omniscan/internal/provider/retry"
	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider"

	"github.com/urfave/cli/v3"
)

func main() {
	cmd.Run(context.Background(), os.Args)
}

var cmd = &cli.Command{
	Name:                  "omni",
	Description:           "Multi-platform VM scanner",
	EnableShellCompletion: true,
	Authors:               []any{"AccuKnox Inc."},
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug logs",
		},
	},
	Commands: []*cli.Command{scanCmd, scheduleCmd},
	Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
		logger := util.NewLogger("info", "text")
		if c.Bool("debug") {
			logger = util.NewLogger("debug", "text")
		}
		slog.SetDefault(logger)
		return ctx, nil
	},
}

var scanCmd = &cli.Command{
	Name: "scan",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox",
		},
		&cli.StringFlag{
			Name:  "endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com//api/v1/artifact/",
		},
		&cli.UintFlag{
			Name:  "tenant-id",
			Usage: "AccuKnox tenant ID",
		},
		&cli.StringFlag{
			Name:  "label",
			Usage: "AccuKnox associated label at the CP",
		},
		&cli.StringFlag{
			Name:      "token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "disable-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "provider",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		var provider provider.Provider

		arg := c.StringArg("provider")
		switch arg {
		case "gcp":
			provider = gcp.NewProvider()
		default:
			return fmt.Errorf("unsupported or unknown provider %q", arg)
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
		if c.Bool("disable-malware-scan") {
			opts = append(opts, job.WithClamscanDisabled())
		}

		summary, err := job.NewScanJob(provider, publisher, opts...).Run(ctx)
		if err != nil {
			return fmt.Errorf("executing scan job: %w", err)
		}

		output, err := jsonMarshalWithError(summary)
		if err != nil {
			return fmt.Errorf("marshalling execution summary to json: %w", err)
		}
		fmt.Println(string(output))

		return nil
	},
}

var scheduleCmd = &cli.Command{
	Name:      "schedule",
	Arguments: scanCmd.Arguments,
	Flags:     scanCmd.Flags,
	Action: func(ctx context.Context, c *cli.Command) error {
		var provider provider.Provider

		arg := c.StringArg("provider")
		switch arg {
		case "gcp":
			provider = gcp.NewProvider()
		default:
			return fmt.Errorf("unsupported or unknown provider %q", arg)
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
		if c.Bool("disable-malware-scan") {
			opts = append(opts, job.WithClamscanDisabled())
		}

		j := job.NewScanJob(provider, publisher, opts...)
		return j.Schedule(ctx, "0 */8 * * *", true)
	},
}
