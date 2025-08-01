package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/accuknox/omniscan/internal/util"

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
	Usage:                 "Multi-platform VM scanner",
	EnableShellCompletion: true,
	Authors:               []any{"AccuKnox Inc."},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "Possible values: debug, info, error",
		},
		&cli.StringFlag{
			Name:  "log-format",
			Value: "text",
			Usage: "Possible values: text, json",
		},
	},
	Commands: []*cli.Command{scanCmd, scheduleCmd},
	Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
		level := c.String("log-level")
		if level != "debug" && level != "info" && level != "error" {
			return ctx, fmt.Errorf("invalid log level %q", level)
		}
		format := c.String("log-format")
		if format != "text" && format != "json" {
			return ctx, fmt.Errorf("invalid log format %q", format)
		}
		slog.SetDefault(util.NewLogger(level, format))
		return ctx, nil
	},
}
