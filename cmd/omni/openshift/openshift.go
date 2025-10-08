package openshift

import "github.com/urfave/cli/v3"

func NewScanCommand() *cli.Command {
	return scanCmd
}

func NewOrchestrateCommand() *cli.Command {
	return orchestrateCmd
}

func NewScheduleCommand() *cli.Command {
	return scheduleCmd
}
