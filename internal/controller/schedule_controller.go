/*
Copyright 2025 AccuKnox Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/accuknox/omniscan/api/v1alpha1"
	"github.com/accuknox/omniscan/pkg/util"
)

const (
	schedulerSAName      = "accuknox-omni-scheduler"
	schedulerRoleName    = "accuknox-omni-scheduler"
	schedulerRoleBinding = "accuknox-omni-scheduler"
)

// ScheduleReconciler reconciles Schedule resources.
type ScheduleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	logger *slog.Logger
}

// +kubebuilder:rbac:groups=omni.accuknox.com,resources=schedules,verbs=get;list;watch;patch;update
// +kubebuilder:rbac:groups=omni.accuknox.com,resources=schedules/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=omni.accuknox.com,resources=schedules/finalizers,verbs=update
// +kubebuilder:rbac:groups=omni.accuknox.com,resources=scans,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;create;update
// +kubebuilder:rbac:groups="kubevirt.io",resources=virtualmachines,verbs=list

// Reconcile performs the main reconciliation loop for Schedule resources.
func (r *ScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := slog.New(logr.ToSlogHandler(log.FromContext(ctx)))
	r.logger = log

	schedule := &v1alpha1.Schedule{}
	if err := r.Get(ctx, req.NamespacedName, schedule); err != nil {
		if apierr.IsNotFound(err) {
			log.DebugContext(ctx, "schedule CR deleted",
				slog.String("name", req.Name))
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get schedule: %w", err)
	}

	if err := r.ensureFinalizer(ctx, schedule); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure finalizer: %w", err)
	}

	if schedule.DeletionTimestamp != nil && !schedule.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, schedule)
	}

	return r.reconcileSchedule(ctx, schedule)
}

// SetupWithManager registers the controller with the manager.
func (r *ScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Schedule{}).
		Owns(&batchv1.CronJob{}).
		Owns(&corev1.ServiceAccount{}).
		Named("schedule").
		Complete(r)
}

// ensureFinalizer adds the schedule finalizer if not present.
func (r *ScheduleReconciler) ensureFinalizer(ctx context.Context, schedule *v1alpha1.Schedule) error {
	patch := client.MergeFrom(schedule.DeepCopy())
	if !ctrlutil.AddFinalizer(schedule, finalizerOmni) {
		return nil
	}
	if err := r.Patch(ctx, schedule, patch); err != nil && !apierr.IsNotFound(err) {
		return fmt.Errorf("patch schedule: %w", err)
	}
	return nil
}

// handleDeletion cleans up resources and removes finalizers during Schedule deletion.
func (r *ScheduleReconciler) handleDeletion(ctx context.Context, schedule *v1alpha1.Schedule) (ctrl.Result, error) {
	cronJob := &batchv1.CronJob{}
	key := types.NamespacedName{
		Name:      schedule.Name,
		Namespace: schedule.Spec.CronJobNamespace,
	}

	if err := r.Get(ctx, key, cronJob); err != nil {
		if !apierr.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("get cronjob: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if err := r.Delete(ctx, cronJob); err != nil && !apierr.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("delete cronjob: %w", err)
	}

	patch := client.MergeFrom(schedule.DeepCopy())
	if ctrlutil.RemoveFinalizer(schedule, finalizerOmni) {
		err := r.Patch(ctx, schedule, patch)
		if err != nil && !apierr.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// reconcileSchedule ensures the CronJob exists and matches the schedule specification.
func (r *ScheduleReconciler) reconcileSchedule(ctx context.Context, schedule *v1alpha1.Schedule) (ctrl.Result, error) {
	if err := r.ensureRBAC(ctx, schedule); err != nil {
		r.updatePhase(ctx, schedule.Name, v1alpha1.SchedulePhaseBootstrapFailed)
		return ctrl.Result{}, fmt.Errorf("ensure rbac: %w", err)
	}

	cronJob, err := r.ensureCronJob(ctx, schedule)
	if err != nil {
		r.updatePhase(ctx, schedule.Name, v1alpha1.SchedulePhaseBootstrapFailed)
		return ctrl.Result{}, fmt.Errorf("ensure cronjob: %w", err)
	}

	if cronJob.Status.LastScheduleTime == nil {
		phase := v1alpha1.SchedulePhaseAwaiting
		if err := r.updatePhase(ctx, schedule.Name, phase); err != nil {
			return ctrl.Result{}, fmt.Errorf("update phase: %w", err)
		}
	}

	if err := r.gcOldScans(ctx, schedule); err != nil {
		return ctrl.Result{}, fmt.Errorf("GC old scans: %w", err)
	}

	nextRequeue, err := r.nextRequeueInterval(schedule)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("calculating next requeue interval: %w", err)
	}

	return ctrl.Result{RequeueAfter: nextRequeue}, nil
}

// ensureRBAC creates the service account, cluster role, and cluster role binding for the scheduler.
func (r *ScheduleReconciler) ensureRBAC(ctx context.Context, schedule *v1alpha1.Schedule) error {
	if err := r.ensureSvcAcct(ctx, schedule); err != nil {
		return fmt.Errorf("ensure service account: %w", err)
	}

	if err := r.ensureClusterRole(ctx, schedule); err != nil {
		return fmt.Errorf("ensure cluster role: %w", err)
	}

	if err := r.ensureClusterRoleBinding(ctx, schedule); err != nil {
		return fmt.Errorf("ensure cluster role binding: %w", err)
	}

	return nil
}

// ensureSvcAcct creates the scheduler service account if it doesn't exist.
func (r *ScheduleReconciler) ensureSvcAcct(ctx context.Context, schedule *v1alpha1.Schedule) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      schedulerSAName,
			Namespace: schedule.Spec.CronJobNamespace,
			Labels:    schedule.GetLabels(),
		},
	}
	if err := ctrl.SetControllerReference(schedule, sa, r.Scheme); err != nil {
		return fmt.Errorf("set controller reference: %w", err)
	}

	if err := r.Create(ctx, sa); err != nil {
		if apierr.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create service account: %w", err)
	}

	return nil
}

// ensureClusterRole creates the scheduler cluster role if it doesn't exist.
func (r *ScheduleReconciler) ensureClusterRole(ctx context.Context, schedule *v1alpha1.Schedule) error {
	cr := &rbacv1.ClusterRole{}
	key := types.NamespacedName{Name: schedulerRoleName}

	desired := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   schedulerRoleName,
			Labels: schedule.GetLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"schedules"},
				Verbs:     []string{"get", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"schedules/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"schedules/finalizers"},
				Verbs:     []string{"update"},
			},
			{
				APIGroups: []string{"omni.accuknox.com"},
				Resources: []string{"scans"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "create", "update"},
			},
			{
				APIGroups: []string{"kubevirt.io"},
				Resources: []string{"virtualmachines"},
				Verbs:     []string{"list"},
			},
		},
	}
	if err := ctrl.SetControllerReference(schedule, desired, r.Scheme); err != nil {
		return fmt.Errorf("set controller reference: %w", err)
	}

	if err := r.Get(ctx, key, cr); err != nil {
		if !apierr.IsNotFound(err) {
			return fmt.Errorf("get cluster role: %w", err)
		}
		if err := r.Create(ctx, desired); err != nil {
			if apierr.IsAlreadyExists(err) {
				goto Patch
			}
			return fmt.Errorf("create cluster role: %w", err)
		}
		return nil
	}

Patch:
	patch := client.MergeFrom(cr.DeepCopy())
	cr.Rules = desired.Rules
	if err := r.Patch(ctx, cr, patch); err != nil {
		return fmt.Errorf("patch cluster role: %w", err)
	}

	return nil
}

// ensureClusterRoleBinding creates the scheduler cluster role binding if it doesn't exist.
func (r *ScheduleReconciler) ensureClusterRoleBinding(ctx context.Context, schedule *v1alpha1.Schedule) error {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   schedulerRoleBinding,
			Labels: schedule.GetLabels(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     schedulerRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      schedulerSAName,
			Namespace: schedule.Spec.CronJobNamespace,
		}},
	}
	if err := ctrl.SetControllerReference(schedule, crb, r.Scheme); err != nil {
		return fmt.Errorf("set controller reference: %w", err)
	}

	if err := r.Create(ctx, crb); err != nil {
		if apierr.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create cluster role binding: %w", err)
	}

	return nil
}

// ensureCronJob creates or updates the CronJob for the schedule.
func (r *ScheduleReconciler) ensureCronJob(ctx context.Context, schedule *v1alpha1.Schedule) (*batchv1.CronJob, error) {
	cronJob := &batchv1.CronJob{}
	key := types.NamespacedName{
		Name:      schedule.Name,
		Namespace: schedule.Spec.CronJobNamespace,
	}

	if err := r.Get(ctx, key, cronJob); err != nil {
		if !apierr.IsNotFound(err) {
			return nil, fmt.Errorf("get cronjob: %w", err)
		}

		cronJob = r.buildCronJob(schedule)
		if err := ctrl.SetControllerReference(schedule, cronJob, r.Scheme); err != nil {
			return nil, fmt.Errorf("set controller reference: %w", err)
		}

		if err := r.Create(ctx, cronJob); err != nil {
			if apierr.IsAlreadyExists(err) {
				goto Patch
			}
			return nil, fmt.Errorf("create cronjob: %w", err)
		}

		return cronJob, nil
	}

Patch:
	desired := r.buildCronJob(schedule)
	patch := client.MergeFrom(cronJob.DeepCopy())
	cronJob.Spec = desired.Spec
	if err := r.Patch(ctx, cronJob, patch); err != nil {
		return nil, fmt.Errorf("patch cronjob: %w", err)
	}

	return cronJob, nil
}

// buildCronJob constructs a CronJob resource from the schedule.
func (r *ScheduleReconciler) buildCronJob(schedule *v1alpha1.Schedule) *batchv1.CronJob {
	jobSpec := r.buildSchedulerJobSpec(schedule)

	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      schedule.Name,
			Namespace: schedule.Spec.CronJobNamespace,
			Labels:    schedule.Labels,
		},
		Spec: batchv1.CronJobSpec{
			Schedule:          schedule.Spec.Schedule,
			TimeZone:          schedule.Spec.TimeZone,
			ConcurrencyPolicy: batchv1.ForbidConcurrent,
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: schedule.Labels,
				},
				Spec: batchv1.JobSpec{
					BackoffLimit: util.Ptr(int32(0)),
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: schedule.Labels,
						},
						Spec: jobSpec,
					},
				},
			},
		},
	}
}

// buildSchedulerJobSpec creates the pod spec for the scheduler job.
func (r *ScheduleReconciler) buildSchedulerJobSpec(schedule *v1alpha1.Schedule) corev1.PodSpec {
	args := []string{"openshift", "schedule", "--name=" + schedule.Name}
	return corev1.PodSpec{
		ServiceAccountName: schedulerSAName,
		RestartPolicy:      corev1.RestartPolicyNever,
		Containers: []corev1.Container{{
			Name:            "scheduler",
			Image:           schedule.Spec.Template.Spec.Image,
			ImagePullPolicy: schedule.Spec.Template.Spec.ImagePullPolicy,
			Command:         []string{"omni"},
			Args:            args,
		}},
	}
}

// updatePhase updates the schedule phase in the status.
func (r *ScheduleReconciler) updatePhase(ctx context.Context, name string, phase v1alpha1.SchedulePhase) error {
	schedule := &v1alpha1.Schedule{}
	key := types.NamespacedName{Name: name}
	if err := r.Get(ctx, key, schedule); err != nil {
		return fmt.Errorf("get schedule: %w", err)
	}
	patch := client.MergeFrom(schedule.DeepCopy())
	schedule.Status.Phase = phase
	return r.Status().Patch(ctx, schedule, patch)
}

// GarbageCollectOldScans deletes all but the latest 3 Scans for each VM.
func (r *ScheduleReconciler) gcOldScans(ctx context.Context, schedule *v1alpha1.Schedule) error {
	var scanList v1alpha1.ScanList
	selector := client.MatchingLabels{
		"omni.accuknox.com/scheduled-by": schedule.Name,
	}

	if err := r.List(ctx, &scanList, &selector); err != nil {
		return fmt.Errorf("listing scans: %w", err)
	}

	vmScans := make(map[string][]v1alpha1.Scan)
	for _, s := range scanList.Items {
		vm := s.Spec.VirtualMachineName
		vmScans[vm] = append(vmScans[vm], s)
	}

	historyLimit := 3
	if desiredLimit := schedule.Spec.ScansHistoryLimit; desiredLimit != nil {
		historyLimit = int(*desiredLimit)
	}

	for _, scans := range vmScans {
		if len(scans) <= historyLimit {
			continue
		}

		sort.Slice(scans, func(i, j int) bool {
			ti := scans[i].CreationTimestamp.Time
			tj := scans[j].CreationTimestamp.Time

			switch {
			case ti.IsZero() && tj.IsZero():
				return scans[i].Name < scans[j].Name
			case ti.IsZero():
				return false
			case tj.IsZero():
				return true
			default:
				return ti.Before(tj)
			}
		})

		oldScans := scans[:len(scans)-3]
		for _, s := range oldScans {
			err := r.Delete(ctx, &s, client.PropagationPolicy(metav1.DeletePropagationBackground))
			if err != nil {
				r.logger.LogAttrs(
					ctx,
					slog.LevelWarn,
					"GC failed. Ignoring...",
					slog.String("scan_name", s.Name),
					slog.String("scan_namespace", s.Namespace),
				)
				continue
			}
			r.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"GC an old scan",
				slog.String("scan_name", s.Name),
				slog.String("scan_namespace", s.Namespace),
			)
		}
	}

	return nil
}

func (r *ScheduleReconciler) nextRequeueInterval(schedule *v1alpha1.Schedule) (time.Duration, error) {
	sched, err := cron.ParseStandard(schedule.Spec.Schedule)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	next := sched.Next(now)
	return next.Sub(now), nil
}
