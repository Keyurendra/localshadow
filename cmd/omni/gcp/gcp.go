package gcp

import "github.com/urfave/cli/v3"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:     "gcp",
		Commands: []*cli.Command{scanCmd, scheduleCmd},
	}
}
