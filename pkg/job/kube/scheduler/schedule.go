package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Keyurendra/shadowtest/api/v1alpha1"
	omniClientset "github.com/Keyurendra/shadowtest/pkg/generated/clientset/versioned"
	omniinformers "github.com/Keyurendra/shadowtest/pkg/generated/informers/externalversions"
	kubeUtil "github.com/Keyurendra/shadowtest/pkg/job/kube/util"
	"github.com/Keyurendra/shadowtest/pkg/provider"
	"github.com/Keyurendra/shadowtest/pkg/resource"
)

const (
	informerResyncPeriod = 30 * time.Second
	gracefulShutdownWait = 5 * time.Minute
)

type Job struct {
	opts
	scheduleName string
	omniClient   omniClientset.Interface
	kubeClient   kubernetes.Interface
	scheme       *runtime.Scheme
}

func New(scheduleName string, fns ...OptFunc) (*Job, error) {
	o := defaultOpts()
	for _, fn := range fns {
		fn(&o)
	}

	kubeClient, err := kubeUtil.NewKubeClient()
	if err != nil {
		return nil, fmt.Errorf("creating kube client: %w", err)
	}

	omniClient, err := kubeUtil.NewOmniClient()
	if err != nil {
		return nil, fmt.Errorf("creating omni client: %w", err)
	}

	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("adding kubernetes types to scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		return nil, fmt.Errorf("adding omni v1alpha1 types to scheme: %w", err)
	}

	return &Job{
		opts:         o,
		scheduleName: scheduleName,
		omniClient:   omniClient,
		kubeClient:   kubeClient,
		scheme:       s,
	}, nil
}

// Run creates and manages Scan resources based on the Schedule's concurrency
// limit.
func (j Job) Run(ctx context.Context, prov provider.Provider) error {
	j.logger.LogAttrs(ctx, slog.LevelInfo, "initializing provider")
	if err := prov.Init(ctx); err != nil {
		return fmt.Errorf("initialization given provider: %w", err)
	}

	schedule, err := j.omniClient.ApiV1alpha1().Schedules().Get(
		ctx,
		j.scheduleName,
		metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("get schedule %s: %w", j.scheduleName, err)
	}

	now := metav1.Now()
	schedule.Status.LastScheduleTime = &now
	if err := j.updateLastScheduleTime(ctx, schedule.Name, now); err != nil {
		return fmt.Errorf("failed to update last schedule time: %w", err)
	}

	vms, err := prov.ListVMs(ctx)
	if err != nil {
		return fmt.Errorf("listing VMs: %w", err)
	}

	if len(vms) == 0 {
		j.logger.LogAttrs(ctx, slog.LevelWarn, "no VMs matched the selector")
		return nil
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"matched VMs",
		slog.Int("count", len(vms)),
	)

	vmsToScan := j.filterRecentlyScannedVMs(ctx, schedule, vms)
	if len(vmsToScan) == 0 {
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"all VMs were recently scanned, nothing to do",
		)
		return nil
	}

	j.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"VMs to scan after filtering",
		slog.Int("count", len(vmsToScan)),
		slog.Int("skipped", len(vms)-len(vmsToScan)),
	)

	return j.manageScanConcurrency(ctx, schedule, vms)
}

// filterRecentlyScannedVMs removes VMs that were recently scanned
// successfully.
func (j Job) filterRecentlyScannedVMs(ctx context.Context, schedule *v1alpha1.Schedule, vms []resource.VM) []resource.VM {
	if schedule.Status.VMScanHistory == nil {
		return vms
	}

	rescanThreshold := calculateRescanThreshold(schedule.Spec.Schedule)
	now := time.Now()
	var filtered []resource.VM

	for _, vm := range vms {
		record, exists := schedule.Status.VMScanHistory[vm.URI]
		if !exists {
			filtered = append(filtered, vm)
			continue
		}
		timeSinceScan := now.Sub(record.LastScanTime.Time)
		if timeSinceScan < rescanThreshold {
			j.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"skipping recently scanned VM",
				slog.String("vm", vm.URI),
				slog.Duration("age", timeSinceScan),
				slog.Duration("threshold", rescanThreshold),
			)
			continue
		}
		filtered = append(filtered, vm)
	}

	return filtered
}

// manageScanConcurrency orchestrates scan creation and lifecycle tracking.
func (j Job) manageScanConcurrency(ctx context.Context, schedule *v1alpha1.Schedule, vms []resource.VM) error {
	state := newState(len(vms))
	state.queueVMs(vms)

	stopCh, err := j.setupInformer(ctx, schedule.Name, state)
	if err != nil {
		return err
	}
	defer close(stopCh)

	shutdownCtx, cancelAdmission := context.WithCancel(ctx)
	defer cancelAdmission()

	admissionDone := make(chan struct{})
	go j.runAdmissionLoop(shutdownCtx, schedule, state, admissionDone)

	return j.waitForCompletion(ctx, schedule, state, cancelAdmission, admissionDone)
}

func (j Job) createScan(ctx context.Context, schedule *v1alpha1.Schedule, vm resource.VM) error {
	ns := nsFromVMUri(vm.URI)
	if err := j.ensureSecret(ctx, schedule, ns); err != nil {
		return fmt.Errorf("ensure secret for VM %s: %w", vm.URI, err)
	}

	metadata := schedule.Spec.Template.Metadata

	labels := make(map[string]string)
	if metadata != nil && metadata.Labels != nil {
		maps.Copy(labels, metadata.Labels)
	}
	labels["omni.accuknox.com/scheduled-by"] = schedule.Name

	annotations := make(map[string]string)
	if metadata != nil && metadata.Annotations != nil {
		maps.Copy(annotations, metadata.Annotations)
	}

	scan := &v1alpha1.Scan{
		ObjectMeta: metav1.ObjectMeta{
			Name:        generateScanName(schedule, vm.URI),
			Namespace:   ns,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: v1alpha1.ScanSpec{
			ClusterName:        schedule.Spec.Template.Spec.ClusterName,
			VirtualMachineName: nameFromVMUri(vm.URI),
			SkipMalwareScan:    schedule.Spec.Template.Spec.SkipMalwareScan,
			Image:              schedule.Spec.Template.Spec.Image,
			ImagePullPolicy:    schedule.Spec.Template.Spec.ImagePullPolicy,
			BackoffLimit:       schedule.Spec.Template.Spec.BackoffLimit,
			Resources:          schedule.Spec.Template.Spec.Resources,
			ArtifactAPI:        schedule.Spec.ArtifactAPI,
		},
	}
	if err := ctrl.SetControllerReference(schedule, scan, j.scheme); err != nil {
		return fmt.Errorf("set controller reference: %w", err)
	}

	_, err := j.omniClient.ApiV1alpha1().Scans(ns).Create(ctx, scan, metav1.CreateOptions{})
	if err != nil {
		if apierr.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create scan: %w", err)
	}

	return nil
}

func (j Job) ensureSecret(ctx context.Context, schedule *v1alpha1.Schedule, destNamespace string) error {
	name := schedule.Spec.ArtifactAPI.Token.SecretRef.Name
	namespace := schedule.Spec.CronJobNamespace
	key := schedule.Spec.ArtifactAPI.Token.SecretRef.Key

	src, err := j.kubeClient.CoreV1().Secrets(namespace).Get(
		ctx,
		name,
		metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("reading secret %s/%s: %w", namespace, name, err)
	}

	token, ok := src.Data[key]
	if !ok {
		return fmt.Errorf("key %s not found in secret %s/%s", key, namespace, name)
	}

	if namespace == destNamespace {
		return nil
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: destNamespace,
			Labels:    schedule.GetLabels(),
		},
		Data: map[string][]byte{
			key: token,
		},
	}
	if err := ctrl.SetControllerReference(schedule, desired, j.scheme); err != nil {
		return fmt.Errorf("set controller reference: %w", err)
	}

	existing, err := j.kubeClient.CoreV1().Secrets(destNamespace).Get(
		ctx,
		src.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		if !apierr.IsNotFound(err) {
			return fmt.Errorf("get existing secret %s/%s: %w", destNamespace, name, err)
		}
		_, err := j.kubeClient.CoreV1().Secrets(destNamespace).Create(
			ctx,
			desired,
			metav1.CreateOptions{},
		)
		if err != nil {
			return fmt.Errorf("create secret: %w", err)
		}
		return nil
	}

	if !bytes.Equal(existing.Data[key], token) {
		existing.Data[key] = token
		_, err := j.kubeClient.CoreV1().Secrets(destNamespace).Update(
			ctx,
			existing,
			metav1.UpdateOptions{},
		)
		if err != nil {
			return fmt.Errorf("update secret: %w", err)
		}
	}

	return nil
}

// setupInformer creates and starts the scan informer with event handlers.
func (j Job) setupInformer(ctx context.Context, scheduleName string, state *state) (chan struct{}, error) {
	labelSelector := fmt.Sprintf("omni.accuknox.com/scheduled-by=%s", scheduleName)
	factory := omniinformers.NewSharedInformerFactoryWithOptions(
		j.omniClient,
		informerResyncPeriod,
		omniinformers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector = labelSelector
		}),
	)

	informer := factory.Api().V1alpha1().Scans().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			j.handleScanUpdate(ctx, newObj, state)
		},
		DeleteFunc: func(obj any) {
			j.handleScanDelete(ctx, obj, state)
		},
	})

	stopCh := make(chan struct{})
	factory.Start(stopCh)

	j.logger.LogAttrs(ctx, slog.LevelInfo, "waiting for informer cache sync")
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		close(stopCh)
		return nil, fmt.Errorf("failed to sync informer cache")
	}
	j.logger.LogAttrs(ctx, slog.LevelInfo, "informer cache synced")

	return stopCh, nil
}

// handleScanUpdate processes scan update events.
func (j Job) handleScanUpdate(ctx context.Context, obj any, state *state) {
	scan, ok := obj.(*v1alpha1.Scan)
	if !ok {
		return
	}

	state.mu.RLock()
	vm, active := state.activeScans[scan.Name]
	state.mu.RUnlock()

	if !active {
		return
	}

	phase := scan.Status.Phase
	if phase == v1alpha1.ScanPhaseSucceeded || phase == v1alpha1.ScanPhaseFailed {
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"scan completed",
			slog.String("scan", scan.Name),
			slog.String("namespace", scan.Namespace),
			slog.String("phase", string(scan.Status.Phase)),
		)
		state.markCompleted(scan.Name, vm, scan.Status.Phase)
		state.signalAdmission()
	}
}

// handleScanDelete processes scan deletion events.
func (j Job) handleScanDelete(ctx context.Context, obj any, state *state) {
	scan, ok := obj.(*v1alpha1.Scan)
	if !ok {
		return
	}

	state.mu.Lock()
	vm, active := state.activeScans[scan.Name]
	state.mu.Unlock()

	if active {
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"scan deleted",
			slog.String("scan", scan.Name),
			slog.String("namespace", scan.Namespace),
		)
		state.markCompleted(scan.Name, vm, v1alpha1.ScanPhaseFailed)
		state.signalAdmission()
	}
}

// runAdmissionLoop continuously admits new scans respecting concurrency
// limits.
func (j Job) runAdmissionLoop(ctx context.Context, schedule *v1alpha1.Schedule, state *state, done chan struct{}) {
	defer close(done)

	concurrency := int(schedule.Spec.Concurrency)

	for {
		for state.activeCount() < concurrency && state.queueLength() > 0 {
			vm, ok := state.dequeueVM()
			if !ok {
				continue
			}

			scanName := generateScanName(schedule, vm.URI)
			j.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"creating scan",
				slog.String("scan", scanName),
				slog.String("vm_uri", vm.URI),
			)

			if err := j.createScan(ctx, schedule, vm); err != nil {
				j.logger.LogAttrs(
					ctx,
					slog.LevelError,
					"failed to create scan",
					slog.String("scan", scanName),
					slog.String("error", err.Error()),
				)
				state.markCompleted(scanName, vm, v1alpha1.ScanPhaseFailed)
				continue
			}

			state.markActive(scanName, vm)
			j.updateActiveScansCount(ctx, schedule.Name, state.activeCount())
		}
		select {
		case <-ctx.Done():
			j.logger.LogAttrs(ctx, slog.LevelInfo, "admission loop shutting down")
			return
		case <-state.doneSignal:
			return
		case <-state.admissionSignal:
		}
	}
}

// waitForCompletion waits for all scans to complete or handles graceful
// shutdown.
func (j Job) waitForCompletion(ctx context.Context, schedule *v1alpha1.Schedule, state *state, cancelAdmission func(), admissionDone chan struct{}) error {
	select {
	case <-state.doneSignal:
		j.logger.LogAttrs(ctx, slog.LevelInfo, "all scans completed")
		j.updateFinalStatus(ctx, schedule.Name, state, true)
		return nil

	case <-ctx.Done():
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"context cancelled, initiating graceful shutdown",
			slog.Int("active_scans", state.activeCount()),
		)

		cancelAdmission()
		<-admissionDone

		j.waitForActiveScans(ctx, state)
		j.updateFinalStatus(context.Background(), schedule.Name, state, false)
		return ctx.Err()
	}
}

// waitForActiveScans waits for active scans to complete with timeout.
func (j Job) waitForActiveScans(ctx context.Context, state *state) {
	shutdownTimer := time.NewTimer(gracefulShutdownWait)
	defer shutdownTimer.Stop()

	select {
	case <-state.doneSignal:
		j.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"graceful shutdown completed, all scans finished",
		)
	case <-shutdownTimer.C:
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"graceful shutdown timed out",
			slog.Int("remaining_scans", state.activeCount()),
		)
	}
}

// updateLastScheduleTime updates the last schedule time in status.
func (j Job) updateLastScheduleTime(ctx context.Context, scheduleName string, t metav1.Time) error {
	err := j.updateScheduleStatus(ctx, scheduleName, func(status *v1alpha1.ScheduleStatus) {
		status.Phase = v1alpha1.SchedulePhaseRunning
		status.LastScheduleTime = &t
	})
	if err != nil {
		j.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"failed to update last schedule time",
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}

// updateActiveScansCount updates the active scans count in status.
func (j Job) updateActiveScansCount(ctx context.Context, scheduleName string, count int) {
	j.updateScheduleStatus(ctx, scheduleName, func(status *v1alpha1.ScheduleStatus) {
		status.ActiveScans = int32(count)
	})
}

// updateFinalStatus updates the schedule status with final results.
func (j Job) updateFinalStatus(ctx context.Context, scheduleName string, state *state, success bool) {
	j.updateScheduleStatus(ctx, scheduleName, func(status *v1alpha1.ScheduleStatus) {
		if status.VMScanHistory == nil {
			status.VMScanHistory = make(map[string]v1alpha1.VMScanRecord)
		}
		maps.Copy(status.VMScanHistory, state.copyHistory())
		status.ActiveScans = int32(state.activeCount())
		// TODO: set awaiting and running states in schedule controller.
		// Currently, if the cronjob fails, the status will be stuck at
		// Running.
		status.Phase = v1alpha1.SchedulePhaseAwaiting
		if success {
			now := metav1.Now()
			status.LastSuccessfulTime = &now
		}
	})
}

// updateScheduleStatus updates the schedule status with the given mutation
// function.
func (j Job) updateScheduleStatus(ctx context.Context, scheduleName string, mutate func(*v1alpha1.ScheduleStatus)) error {
	c := j.omniClient.ApiV1alpha1().Schedules()
	schedule, err := c.Get(ctx, scheduleName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get schedule: %w", err)
	}
	mutate(&schedule.Status)
	_, err = c.UpdateStatus(ctx, schedule, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update schedule status: %w", err)
	}
	return nil
}
