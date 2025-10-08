package aws

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/cloud"
	"github.com/accuknox/omniscan/pkg/provider/aws"
	"github.com/accuknox/omniscan/pkg/provider/retry"
	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/resource"
)

var scheduleCmd = &cli.Command{
	Name:  "schedule",
	Flags: util.CloudScheduleCmdFlags(),
	Action: func(ctx context.Context, c *cli.Command) error {
		provider, err := aws.NewProvider(aws.WithVMFilter(resource.Filter{
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

		opts := []cloud.OptFunc{
			cloud.WithConcurrency(c.Uint("concurrency")),
			cloud.WithPrometheusMetricsPort(c.Uint16("prometheus-metrics-port")),
		}
		if c.Bool("skip-malware-scan") {
			opts = append(opts, cloud.WithClamscanDisabled())
		}
		if c.Bool("enable-prometheus-metrics") {
			opts = append(opts, cloud.WithPrometheusMetrics())
		}

		job, err := cloud.NewJob(provider, publisher, opts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}
		return job.Schedule(
			ctx,
			c.String("crontab"), c.Bool("trigger-immediately"),
		)
	},
}
