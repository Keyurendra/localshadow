package db

import "github.com/urfave/cli/v3"

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:     "db",
		Commands: []*cli.Command{downloadCmd},
	}
}
