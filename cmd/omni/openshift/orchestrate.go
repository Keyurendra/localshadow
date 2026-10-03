package openshift

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	omniClientset "github.com/Keyurendra/shadowtest/pkg/generated/clientset/versioned"
	"github.com/Keyurendra/shadowtest/pkg/job/kube/orchestrator"
	"github.com/Keyurendra/shadowtest/pkg/provider/openshift"
	"github.com/Keyurendra/shadowtest/pkg/provider/retry"
)

var orchestrateCmd = &cli.Command{
	Name: "orchestrate",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "namespace",
			Required: true,
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		namespace := c.String("namespace")
		name := c.String("name")

		provider, err := openshift.NewProvider(name, namespace)
		if err != nil {
			return fmt.Errorf("setting up provider: %w", err)
		}
		provider = retry.NewProvider(provider)

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return fmt.Errorf("creating kube config: %w", err)
		}

		omniClient, err := omniClientset.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("creating omni client: %w", err)
		}

		obj, err := omniClient.ApiV1alpha1().Scans(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("GET Scan resource: %w", err)
		}

		job := orchestrator.New(obj.Name, obj.Namespace, provider)
		if err != nil {
			return fmt.Errorf("creating job: %w", err)
		}

		return job.Run(ctx)
	},
}
