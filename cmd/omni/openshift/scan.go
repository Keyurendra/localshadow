package openshift

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/urfave/cli/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/accuknox/omniscan/cmd/omni/util"
	omniClientset "github.com/accuknox/omniscan/pkg/generated/clientset/versioned"
	"github.com/accuknox/omniscan/pkg/job/kube/scanner"
	"github.com/accuknox/omniscan/pkg/provider/openshift"
	"github.com/accuknox/omniscan/pkg/provider/retry"
	"github.com/accuknox/omniscan/pkg/publisher/file"
)

var scanCmd = &cli.Command{
	Name: "scan",
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name:      "mountpoint",
			Value:     "/mnt/accuknox",
			UsageText: "Root mountpoint to scan",
			Config:    cli.StringConfig{TrimSpace: true},
		},
	},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "namespace",
			Required: true,
		},
		&cli.StringFlag{
			Name: "volumesnapshotclass",
		},
		&cli.BoolFlag{
			Name:  "local-publisher",
			Usage: "Store artifacts locally only",
		},
		&cli.StringFlag{
			Name:      "local-publisher-store-path",
			Usage:     "Path to local publisher's store directory",
			TakesFile: true,
			Value:     "/var/lib/accuknox-omni/",
		},
		&cli.StringFlag{
			Name:  "artifact-endpoint",
			Usage: "AccuKnox artifact API endpoint",
			Value: "https://cspm.accuknox.com/api/v1/artifact/",
		},
		&cli.UintFlag{
			Name:        "tenant-id",
			Usage:       "AccuKnox tenant ID",
			HideDefault: true,
		},
		&cli.StringFlag{
			Name:  "artifact-label",
			Usage: "Label to associate with the artifact",
		},
		&cli.StringFlag{
			Name:      "artifact-token-file",
			Usage:     "Path to AccuKnox artifact API JWT auth token",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "skip-malware-scan",
			Usage: "Scan only for vulnerabilities",
		},
		&cli.StringFlag{
			Name:      "vuln-db-directory",
			Usage:     "Path to vulnerability scanner's database directory",
			Value:     "/var/lib/accuknox-omni",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:      "clamav-db-directory",
			Value:     "/var/lib/clamav",
			Usage:     "Path to ClamAV database directory",
			TakesFile: true,
		},
		&cli.BoolFlag{
			Name:  "use-external-trivy",
			Usage: "Use external trivy. Must be in PATH",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		namespace := c.String("namespace")
		name := c.String("name")

		mountpoint := c.StringArg("mountpoint")
		if mountpoint == "" {
			return fmt.Errorf("missing mountpoint")
		}

		var osOpts []openshift.OptFunc
		if vsc := c.String("volumesnapshotclass"); vsc != "" {
			osOpts = append(osOpts, openshift.WithVolumeSnapshotClassName(vsc))
		}

		provider, err := openshift.NewProvider(name, namespace, osOpts...)
		if err != nil {
			return fmt.Errorf("setting up provider: %w", err)
		}
		provider = retry.NewProvider(provider)

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return fmt.Errorf("creating kube config: %w", err)
		}

		client, err := omniClientset.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("creating omni client: %w", err)
		}

		obj, err := client.
			ApiV1alpha1().
			Scans(namespace).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("GET Scan resource: %w", err)
		}

		publisher := file.NewPublisher(c.String("local-publisher-store-path"))
		if !c.Bool("local-publisher") {
			var err error
			publisher, err = util.CreateCSPMPublisher(c)
			if err != nil {
				return err
			}
		}

		scOpts := []scanner.OptFunc{
			scanner.WithVulnDBDirectory(c.String("vuln-db-directory")),
			scanner.WithClamAVDBDirectory(c.String("clamav-db-directory")),
		}
		if c.Bool("skip-malware-scan") {
			scOpts = append(scOpts, scanner.WithMalwareScanDisabled())
		}
		if c.Bool("use-external-trivy") {
			scOpts = append(scOpts, scanner.WithUseExternalTrivy())
		}

		job := scanner.New(obj.Name, obj.Namespace, provider, publisher, scOpts...)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		summary, err := job.Run(ctx, mountpoint)
		if err != nil {
			return fmt.Errorf("executing scan job: %w", err)
		}

		output, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling execution summary to json: %w", err)
		}
		fmt.Println(string(output))

		for _, err := range summary {
			anyNonNil := err.OrchestrationError != nil ||
				err.MalwareScanError != nil ||
				err.VulnScanError != nil ||
				err.ArtifactAPIError != nil
			if anyNonNil {
				return fmt.Errorf("non-zero exit code")
			}
		}

		return nil
	},
}
