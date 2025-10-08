package aws

import "github.com/urfave/cli/v3"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:     "aws",
		Commands: []*cli.Command{scanCmd, scheduleCmd},
	}
}
