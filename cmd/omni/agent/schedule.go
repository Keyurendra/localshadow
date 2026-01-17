package agent

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	cmdUtil "github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/agent"
	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/util"
)

var scheduleCmd = &cli.Command{
	Name:      "schedule",
	Flags:     cmdUtil.AgentScheduleCmdFlags(),
	Arguments: cmdUtil.AgentScheduleCmdArgs(),
	Action: func(ctx context.Context, c *cli.Command) error {
		publisher := file.NewPublisher(c.String("local-publisher-store-path"))
		if !c.Bool("local-publisher") {
			var err error
			publisher, err = cmdUtil.CreateCSPMPublisher(c)
			if err != nil {
				return err
			}
		}

		skipMalwareScan := c.Bool("skip-malware-scan")
		skipVulnScan := c.Bool("skip-vuln-scan")
		if skipVulnScan && skipMalwareScan {
			return fmt.Errorf("atleast one scaner should be enabled")
		}

		opts := []agent.OptFunc{
			agent.WithVulnDBDirectory(c.String("vuln-db-directory")),
			agent.WithMalwareScanTargetDirectory(c.String("malware-scan-target-directory")),
			agent.WithOverrideHostname(c.String("override-hostname")),
		}
		if skipMalwareScan {
			opts = append(opts, agent.WithMalwareScanDisabled())
		}
		if skipVulnScan {
			opts = append(opts, agent.WithVulnScanDisabled())
		}

		job, err := agent.NewJob(publisher, opts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		rootfs := c.StringArg("rootfs")
		if rootfs == "" {
			rootfs, err = util.FindRootFS()
			if err != nil {
				return fmt.Errorf("determining rootfs: %w", err)
			}
		}

		return job.Schedule(ctx, rootfs, c.String("crontab"), c.Bool("trigger-immediately"))
	},
}
