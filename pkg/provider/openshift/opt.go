package openshift

import (
	"fmt"
	"log/slog"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	omniv1alpha1 "github.com/Keyurendra/shadowtest/api/v1alpha1"
)

type OptFunc func(*opts) error

type opts struct {
	logger                  *slog.Logger
	labelsSelector          labels.Selector
	nsFilter                func(ns string) bool
	waitReadyTimeout        time.Duration
	volumeSnapshotClassName *string
}

func WithLogger(l *slog.Logger) OptFunc {
	return func(o *opts) error {
		if l == nil {
			return nil
		}
		o.logger = l
		return nil
	}
}

func WithVMLabelSelector(ls metav1.LabelSelector) OptFunc {
	return func(o *opts) error {
		selector, err := metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			return err
		}
		o.labelsSelector = selector
		return nil
	}
}

func WithNamespaceSelector(nsel omniv1alpha1.NamespaceSelector) OptFunc {
	return func(o *opts) error {
		inOp := omniv1alpha1.NamespaceSelectorOpIn
		notInOp := omniv1alpha1.NamespaceSelectorOpNotIn
		if nsel.Operator != inOp && nsel.Operator != notInOp {
			return fmt.Errorf("invalid namespace selector operator %s", nsel.Operator)
		}
		if len(nsel.Values) == 0 {
			return fmt.Errorf("missing namespace selector values")
		}
		nsFilter := func(ns string) bool {
			switch nsel.Operator {
			case inOp:
				return slices.Contains(nsel.Values, ns)
			case notInOp:
				return !slices.Contains(nsel.Values, ns)
			}
			return false
		}
		o.nsFilter = nsFilter
		return nil
	}
}

func WithWaitReadyTimeout(timeout time.Duration) OptFunc {
	return func(o *opts) error {
		if timeout == 0 {
			return fmt.Errorf("timeout must be be > 0")
		}
		o.waitReadyTimeout = timeout
		return nil
	}
}

func WithVolumeSnapshotClassName(class string) OptFunc {
	return func(o *opts) error {
		if class == "" {
			return fmt.Errorf("volumeSnapshotClassName cannot be empty")
		}
		o.volumeSnapshotClassName = &class
		return nil
	}
}

func defaultOpts() opts {
	return opts{
		logger:                  slog.Default().With("provider", "openshift"),
		labelsSelector:          nil,
		nsFilter:                func(ns string) bool { return true }, // all namespaces
		waitReadyTimeout:        time.Hour,
		volumeSnapshotClassName: nil,
	}
}
