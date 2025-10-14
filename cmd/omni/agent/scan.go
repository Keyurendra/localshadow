package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/agent"
	"github.com/accuknox/omniscan/pkg/publisher/file"
)

var scanCmd = &cli.Command{
	Name:  "scan",
	Flags: util.AgentScanCmdFlags(),
	Action: func(ctx context.Context, c *cli.Command) error {
		publisher := file.NewPublisher(c.String("local-publisher-store-path"))
		if !c.Bool("local-publisher") {
			var err error
			publisher, err = util.CreateCSPMPublisher(c)
			if err != nil {
				return err
			}
		}

		opts := []agent.OptFunc{
			agent.WithVulnDBDirectory(c.String("vuln-db-directory")),
		}
		if c.Bool("skip-malware-scan") {
			opts = append(opts, agent.WithMalwareScanDisabled())
		}

		job, err := agent.NewJob(publisher, opts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		summary, err := job.Run(ctx, "/")
		if err != nil {
			return fmt.Errorf("executing scan job: %w", err)
		}

		output, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling execution summary to json: %w", err)
		}

		fmt.Println(string(output))

		return nil
	},
}
