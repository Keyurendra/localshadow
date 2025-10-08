package gcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/cloud"
	"github.com/accuknox/omniscan/pkg/provider/gcp"
	"github.com/accuknox/omniscan/pkg/provider/retry"
	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/resource"
)

var scanCmd = &cli.Command{
	Name:  "scan",
	Flags: util.CloudScanCmdFlags(),
	Action: func(ctx context.Context, c *cli.Command) error {
		provider, err := gcp.NewProvider(gcp.WithVMFilter(resource.Filter{
			Name:   c.String("vm-name-regex"),
			Labels: c.StringMap("vm-label-regex"),
		}))
		if err != nil {
			return fmt.Errorf("setting up provider: %w", err)
		}
		provider = retry.NewProvider(provider)

		publisher := file.NewPublisher(c.String("local-publisher-store-path"))
		if !c.Bool("local-publisher") {
			var err error
			publisher, err = util.CreateCSPMPublisher(c)
			if err != nil {
				return err
			}
		}

		opts := []cloud.OptFunc{cloud.WithConcurrency(c.Uint("concurrency"))}
		if c.Bool("skip-malware-scan") {
			opts = append(opts, cloud.WithClamscanDisabled())
		}

		job, err := cloud.NewJob(provider, publisher, opts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		summary, err := job.Run(ctx)
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
