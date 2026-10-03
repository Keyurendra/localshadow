package openshift

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	omniClientset "github.com/Keyurendra/shadowtest/pkg/generated/clientset/versioned"
	"github.com/Keyurendra/shadowtest/pkg/job/kube/scheduler"
	"github.com/Keyurendra/shadowtest/pkg/provider/openshift"
	"github.com/Keyurendra/shadowtest/pkg/provider/retry"
)

var scheduleCmd = &cli.Command{
	Name: "schedule",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "name",
			Required: true,
		},
		&cli.StringFlag{
			Name: "volumesnapshotclass",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		name := c.String("name")

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return fmt.Errorf("creating kube config: %w", err)
		}

		client, err := omniClientset.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("creating omni client: %w", err)
		}

		schedule, err := client.ApiV1alpha1().Schedules().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get Schedule %s: %w", name, err)
		}

		var opts []openshift.OptFunc
		if vsc := c.String("volumesnapshotclass"); vsc != "" {
			opts = append(opts, openshift.WithVolumeSnapshotClassName(vsc))
		}
		if nsel := schedule.Spec.NamespaceSelector; nsel != nil {
			opts = append(opts, openshift.WithNamespaceSelector(*nsel))
		}
		if vmsel := schedule.Spec.VMSelector; vmsel != nil {
			opts = append(opts, openshift.WithVMLabelSelector(*vmsel))
		}

		provider, err := openshift.NewProvider("", metav1.NamespaceAll, opts...)
		if err != nil {
			return fmt.Errorf("setting up provider: %w", err)
		}
		provider = retry.NewProvider(provider)

		job, err := scheduler.New(name)
		if err != nil {
			return fmt.Errorf("creating scheduler: %w", err)
		}

		return job.Run(ctx, provider)
	},
}
