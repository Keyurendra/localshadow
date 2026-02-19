package azure

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/accuknox/omniscan/cmd/omni/util"
	"github.com/accuknox/omniscan/pkg/job/cloud"
	"github.com/accuknox/omniscan/pkg/provider/azure"
	"github.com/accuknox/omniscan/pkg/provider/retry"
	"github.com/accuknox/omniscan/pkg/publisher/file"
	"github.com/accuknox/omniscan/pkg/resource"
)

var scheduleCmd = &cli.Command{
	Name:  "schedule",
	Flags: util.CloudScheduleCmdFlags(),
	Action: func(ctx context.Context, c *cli.Command) error {
		provider, err := azure.NewProvider(azure.WithVMFilter(resource.Filter{
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
			cloud.WithVulnDBDirectory(c.String("vuln-db-directory")),
		}
		if c.Bool("skip-malware-scan") {
			opts = append(opts, cloud.WithMalwareScanDisabled())
		}
		if c.Bool("enable-container-image-scan") {
			opts = append(opts, cloud.WithContainerVulnScanEnabled())
		}
		if c.Bool("container-image-scan-remote-fallback") {
			opts = append(opts, cloud.WithContainerImageScanRemoteFallback())
		}
		if c.Bool("enable-prometheus-metrics") {
			opts = append(opts, cloud.WithPrometheusMetrics())
		}
		if c.Bool("use-external-trivy") {
			opts = append(opts, cloud.WithUseExternalTrivy())
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
