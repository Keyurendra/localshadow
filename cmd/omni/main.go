package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/job"
	"github.com/accuknox/omniscan/internal/provider/gcp"
	"github.com/accuknox/omniscan/internal/provider/retry"
	"github.com/accuknox/omniscan/internal/util"
	"github.com/accuknox/omniscan/pkg/provider"
	"github.com/accuknox/omniscan/pkg/provider/resource"

	"github.com/urfave/cli/v3"
)

func main() {
	err := cmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

var cmd = &cli.Command{
	Name:                  "omni",
	Usage:                 "Multi-platform VM Scanner",
	EnableShellCompletion: true,
	Authors:               []any{"AccuKnox Inc."},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Usage: "Set log level: debug, info, warn, error",
			Value: "info",
		},
		&cli.StringFlag{
			Name:  "log-format",
			Usage: "Set log format: text, json, pretty",
			Value: "text",
		},
		&cli.BoolFlag{
			Name:  "log-with-source",
			Usage: "Include source file and line number in log messages",
			Value: false,
		},
	},
	Commands: subCommands(),
	Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
		level := c.String("log-level")
		if level != "debug" && level != "info" && level != "error" {
			return ctx, fmt.Errorf("invalid log level %q", level)
		}
		format := c.String("log-format")
		if format != "text" && format != "json" && format != "pretty" {
			return ctx, fmt.Errorf("invalid log format %q", format)
		}
		withSource := c.Bool("log-with-source")
		slog.SetDefault(util.NewLogger(level, format, withSource))
		return ctx, nil
	},
}

func subCommands() []*cli.Command {
	flags := []cli.Flag{
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
	args := []cli.Argument{
		&cli.StringArg{
			Name:      "provider",
			UsageText: "gcp",
		},
	}
	action := func(name string) cli.ActionFunc {
		return func(ctx context.Context, c *cli.Command) error {
			arg := c.StringArg("provider")
			if arg == "" {
				return fmt.Errorf("missing `provider`")
			}

			var provider provider.Provider
			var err error

			switch arg {
			case "gcp":
				provider, err = gcp.NewProvider(gcp.WithVMFilter(resource.Filter{
					Name:   c.String("vm-name-regex"),
					Labels: c.StringMap("vm-label-regex"),
				}))
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

			switch name {
			case "scan":
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
			case "schedule":
				j := job.NewScanJob(provider, publisher, opts...)
				return j.Schedule(ctx, c.String("crontab"), c.Bool("trigger-immediately"))
			default:
				return nil
			}
		}
	}
	return []*cli.Command{
		{
			Name:      "scan",
			Usage:     "Perform a one-time scan",
			Action:    action("scan"),
			Arguments: args,
			Flags:     flags,
		},
		{
			Name:      "schedule",
			Usage:     "Schedule recurring scans",
			Action:    action("schedule"),
			Arguments: args,
			Flags: append(flags,
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
			),
		},
	}
}
