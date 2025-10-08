package azure

import "github.com/urfave/cli/v3"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:     "azure",
		Commands: []*cli.Command{scanCmd, scheduleCmd},
	}
}
