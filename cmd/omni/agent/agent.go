package agent

import "github.com/urfave/cli/v3"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:     "agent",
		Commands: []*cli.Command{scanCmd, scheduleCmd},
	}
}
