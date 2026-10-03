package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/Keyurendra/shadowtest/cmd/omni/util"
	"github.com/Keyurendra/shadowtest/pkg/job/cloud"
	"github.com/Keyurendra/shadowtest/pkg/provider/azure"
	"github.com/Keyurendra/shadowtest/pkg/provider/retry"
	"github.com/Keyurendra/shadowtest/pkg/publisher/file"
	"github.com/Keyurendra/shadowtest/pkg/resource"
)

var scanCmd = &cli.Command{
	Name:  "scan",
	Flags: util.CloudScanCmdFlags(),
	Action: func(ctx context.Context, c *cli.Command) error {
		provider, err := azure.NewProvider(azure.WithVMFilter(resource.Filter{
			Name:    c.String("vm-name-regex"),
			Labels:  c.StringMap("vm-label-regex"),
			MultiAZ: c.Bool("multi-az-support"),
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
			cloud.WithVulnDBDirectory(c.String("vuln-db-directory")),
		}
		if c.IsSet("cluster-id") {
			opts = append(opts, cloud.WithClusterID(c.Int("cluster-id")))
		}
		if c.IsSet("cluster-name") {
			opts = append(opts, cloud.WithClusterName(c.String("cluster-name")))
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
		if c.Bool("use-external-trivy") {
			opts = append(opts, cloud.WithUseExternalTrivy())
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
