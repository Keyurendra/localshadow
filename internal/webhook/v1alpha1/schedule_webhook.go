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

package v1alpha1

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/accuknox/omniscan/api/v1alpha1"
	"github.com/accuknox/omniscan/pkg/util"
)

// SetupScheduleWebhookWithManager registers the webhook for Schedule in the manager.
func SetupScheduleWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&v1alpha1.Schedule{}).
		WithValidator(&ScheduleCustomValidator{
			KubeClient: mgr.GetAPIReader(),
		}).
		WithDefaulter(&ScheduleCustomDefaulter{
			DefaultConcurrency:       3,
			DefaultSchedule:          "@daily",
			DefaultScansHistoryLimit: util.Ptr(int32(3)),
			DefaultSkipMalwareScan:   util.Ptr(true),
			DefaultImage:             "public.ecr.aws/k9v9d5v2/omni:latest",
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-omni-accuknox-com-v1alpha1-schedule,mutating=true,failurePolicy=fail,sideEffects=None,groups=omni.accuknox.com,resources=schedules,verbs=create;update,versions=v1alpha1,name=mschedule-v1alpha1.kb.io,admissionReviewVersions=v1
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get

// ScheduleCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Schedule when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type ScheduleCustomDefaulter struct {
	DefaultConcurrency       int32
	DefaultSchedule          string
	DefaultScansHistoryLimit *int32
	DefaultSkipMalwareScan   *bool
	DefaultImage             string
}

var _ webhook.CustomDefaulter = &ScheduleCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Schedule.
func (d *ScheduleCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	schedule, ok := obj.(*v1alpha1.Schedule)
	if !ok {
		return fmt.Errorf("expected an Schedule object but got %T", obj)
	}

	if schedule.Spec.Concurrency == 0 {
		schedule.Spec.Concurrency = d.DefaultConcurrency
	}

	if schedule.Spec.Schedule == "" {
		schedule.Spec.Schedule = d.DefaultSchedule
	}

	if schedule.Spec.ScansHistoryLimit == nil {
		schedule.Spec.ScansHistoryLimit = d.DefaultScansHistoryLimit
	}

	if schedule.Spec.Template.Spec.SkipMalwareScan == nil {
		schedule.Spec.Template.Spec.SkipMalwareScan = d.DefaultSkipMalwareScan
	}

	if schedule.Spec.Template.Spec.Image == "" {
		schedule.Spec.Template.Spec.Image = d.DefaultImage
	}

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-omni-accuknox-com-v1alpha1-schedule,mutating=false,failurePolicy=fail,sideEffects=None,groups=omni.accuknox.com,resources=schedules,verbs=create;update,versions=v1alpha1,name=vschedule-v1alpha1.kb.io,admissionReviewVersions=v1

// ScheduleCustomValidator struct is responsible for validating the Schedule resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ScheduleCustomValidator struct {
	KubeClient client.Reader
}

var _ webhook.CustomValidator = &ScheduleCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Schedule.
func (v *ScheduleCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	schedule, ok := obj.(*v1alpha1.Schedule)
	if !ok {
		return nil, fmt.Errorf("expected a Schedule object but got %T", obj)
	}
	allErrs := v.validateResource(ctx, schedule)
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "omni.accuknox.com", Kind: "Schedule"},
			schedule.Name,
			allErrs,
		)
	}
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Schedule.
func (v *ScheduleCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldSchedule, ok := oldObj.(*v1alpha1.Schedule)
	if !ok {
		return nil, fmt.Errorf("expected a Schedule object for the oldObj but got %T", oldObj)
	}

	newSchedule, ok := newObj.(*v1alpha1.Schedule)
	if !ok {
		return nil, fmt.Errorf("expected a Schedule object for the newObj but got %T", newObj)
	}

	allErrs := v.validateResource(ctx, newSchedule)
	if newSchedule.Spec.CronJobNamespace != oldSchedule.Spec.CronJobNamespace {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("cronJobNamespace"),
			"field is immutable",
		))
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "omni.accuknox.com", Kind: "Schedule"},
			newSchedule.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Schedule.
func (v *ScheduleCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *ScheduleCustomValidator) validateResource(ctx context.Context, s *v1alpha1.Schedule) field.ErrorList {
	var allErrs field.ErrorList

	if err := v.validateCronjobNS(ctx, s); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := validateCronSchedule(s.Spec.Schedule); err != nil {
		allErrs = append(allErrs, err)
	}

	if errs := validateTimeZone(s.Spec.TimeZone); errs != nil {
		allErrs = append(allErrs, errs...)
	}

	err := validateArtifactToken(
		ctx,
		v.KubeClient,
		s.Spec.ArtifactAPI.Token,
		s.Spec.CronJobNamespace,
	)
	if err != nil {
		allErrs = append(allErrs, err)
	}

	return allErrs
}

func (v *ScheduleCustomValidator) validateCronjobNS(ctx context.Context, s *v1alpha1.Schedule) *field.Error {
	key := types.NamespacedName{Name: s.Spec.CronJobNamespace}
	obj := &corev1.Namespace{}
	path := field.NewPath("spec").Child("cronJobNamespace")
	if err := v.KubeClient.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return field.NotFound(path, s.Spec.CronJobNamespace)
		}
		return field.InternalError(
			path,
			fmt.Errorf("failed to check if namespace exists: %v", err),
		)
	}
	return nil
}

func validateCronSchedule(schedule string) *field.Error {
	path := field.NewPath("spec").Child("schedule")
	if _, err := cron.ParseStandard(schedule); err != nil {
		return field.Invalid(path, schedule, err.Error())
	}
	return nil
}

// https://github.com/kubernetes/kubernetes/blob/c70011/pkg/apis/batch/validation/validation.go#L859
var validTimeZoneCharacters = regexp.MustCompile(`^[A-Za-z\.\-_0-9+]{1,14}$`)

func validateTimeZone(timeZone *string) field.ErrorList {
	path := field.NewPath("spec").Child("timeZone")

	allErrs := field.ErrorList{}
	if timeZone == nil {
		return allErrs
	}

	if len(*timeZone) == 0 {
		allErrs = append(allErrs, field.Invalid(
			path,
			timeZone,
			"timeZone must be nil or non-empty string",
		))
		return allErrs
	}

	for part := range strings.SplitSeq(*timeZone, "/") {
		hasValidChars := validTimeZoneCharacters.MatchString(part)
		if part == "." || part == ".." || strings.HasPrefix(part, "-") || !hasValidChars {
			allErrs = append(allErrs, field.Invalid(
				path,
				timeZone,
				fmt.Sprintf("unknown time zone %s", *timeZone),
			))
			return allErrs
		}
	}

	if strings.EqualFold(*timeZone, "Local") {
		allErrs = append(allErrs, field.Invalid(
			path,
			timeZone,
			"timeZone must be an explicit time zone as defined in https://www.iana.org/time-zones",
		))
	}

	if _, err := time.LoadLocation(*timeZone); err != nil {
		allErrs = append(allErrs, field.Invalid(path, timeZone, err.Error()))
	}

	return allErrs
}
