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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"kubevirt.io/client-go/kubevirt"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/accuknox/omniscan/api/v1alpha1"
	"github.com/accuknox/omniscan/pkg/util"
)

// SetupScanWebhookWithManager registers the webhook for Scan in the manager.
func SetupScanWebhookWithManager(mgr ctrl.Manager, image string) error {
	kubevirtClient, err := kubevirt.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("creating kubevirt client: %w", err)
	}
	return ctrl.NewWebhookManagedBy(mgr, &v1alpha1.Scan{}).
		WithCustomValidator(&ScanCustomValidator{
			KubeClient:     mgr.GetAPIReader(),
			KubevirtClient: kubevirtClient,
		}).
		WithCustomDefaulter(&ScanCustomDefaulter{
			DefaultSkipMalwareScan: util.Ptr(true),
			DefaultImage:           image,
		}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-omni-accuknox-com-v1alpha1-scan,mutating=true,failurePolicy=fail,sideEffects=None,groups=omni.accuknox.com,resources=scans,verbs=create;update,versions=v1alpha1,name=mscan-v1alpha1.kb.io,admissionReviewVersions=v1

// ScanCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind Scan when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type ScanCustomDefaulter struct {
	DefaultSkipMalwareScan *bool
	DefaultImage           string
}

var _ webhook.CustomDefaulter = &ScanCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind Scan.
func (d *ScanCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	scan, ok := obj.(*v1alpha1.Scan)
	if !ok {
		return fmt.Errorf("expected an Scan object but got %T", obj)
	}
	if scan.Spec.Image == "" {
		scan.Spec.Image = d.DefaultImage
	}
	if scan.Spec.SkipMalwareScan == nil {
		scan.Spec.SkipMalwareScan = d.DefaultSkipMalwareScan
	}
	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-omni-accuknox-com-v1alpha1-scan,mutating=false,failurePolicy=fail,sideEffects=None,groups=omni.accuknox.com,resources=scans,verbs=create;update,versions=v1alpha1,name=vscan-v1alpha1.kb.io,admissionReviewVersions=v1

// ScanCustomValidator struct is responsible for validating the Scan resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ScanCustomValidator struct {
	KubeClient     client.Reader
	KubevirtClient kubevirt.Interface
}

var _ webhook.CustomValidator = &ScanCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type Scan.
func (v *ScanCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	scan, ok := obj.(*v1alpha1.Scan)
	if !ok {
		return nil, fmt.Errorf("expected a Scan object but got %T", obj)
	}

	var allErrs field.ErrorList

	if err := v.validateVM(ctx, scan); err != nil {
		allErrs = append(allErrs, err)
	}

	err := validateArtifactToken(ctx, v.KubeClient, scan.Spec.ArtifactAPI.Token, scan.Namespace)
	if err != nil {
		allErrs = append(allErrs, err)
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "omni.accuknox.com", Kind: "Scan"},
			scan.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type Scan.
func (v *ScanCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldScan, ok := oldObj.(*v1alpha1.Scan)
	if !ok {
		return nil, fmt.Errorf("expected a Scan object for the oldObj but got %T", oldObj)
	}

	newScan, ok := newObj.(*v1alpha1.Scan)
	if !ok {
		return nil, fmt.Errorf("expected a Scan object for the newObj but got %T", newObj)
	}

	var allErrs field.ErrorList

	if newScan.Spec.ClusterName != oldScan.Spec.ClusterName {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("clusterName"),
			"spec is immutable",
		))
	}

	if newScan.Spec.VirtualMachineName != oldScan.Spec.VirtualMachineName {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("virtualMachineName"),
			"spec is immutable",
		))
	}

	if !ptrCompareEqual(newScan.Spec.SkipMalwareScan, oldScan.Spec.SkipMalwareScan) {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("skipMalwareScan"),
			"spec is immutable",
		))
	}

	if newScan.Spec.Image != oldScan.Spec.Image {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("image"),
			"spec is immutable",
		))
	}

	if newScan.Spec.ImagePullPolicy != oldScan.Spec.ImagePullPolicy {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("imagePullPolicy"),
			"spec is immutable",
		))
	}

	if !ptrCompareEqual(newScan.Spec.BackoffLimit, oldScan.Spec.BackoffLimit) {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("backoffLimit"),
			"spec is immutable",
		))
	}

	if !resourcesEqual(newScan.Spec.Resources, oldScan.Spec.Resources) {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("resources"),
			"spec is immutable",
		))
	}

	if !artifactAPIEqual(newScan.Spec.ArtifactAPI, oldScan.Spec.ArtifactAPI) {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("artifactAPI"),
			"spec is immutable",
		))
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "omni.accuknox.com", Kind: "Scan"},
			newScan.Name,
			allErrs,
		)
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type Scan.
func (v *ScanCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *ScanCustomValidator) validateVM(ctx context.Context, scan *v1alpha1.Scan) *field.Error {
	vmPath := field.NewPath("spec").Child("virtualMachineName")
	vmName := scan.Spec.VirtualMachineName

	_, err := v.KubevirtClient.
		KubevirtV1().
		VirtualMachines(scan.Namespace).
		Get(ctx, vmName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return field.NotFound(vmPath, vmName)
		}
		return field.InternalError(
			vmPath,
			fmt.Errorf("failed to check if VirtualMachine exists: %w", err),
		)
	}

	return nil
}

// ptrCompareEqual compares two bool/int32 pointers.
func ptrCompareEqual[T bool | int32](a, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// resourcesEqual compares two ResourceRequirements.
func resourcesEqual(a, b corev1.ResourceRequirements) bool {
	return a.Limits.Cpu().Cmp(*b.Limits.Cpu()) == 0 &&
		a.Limits.Memory().Cmp(*b.Limits.Memory()) == 0 &&
		a.Requests.Cpu().Cmp(*b.Requests.Cpu()) == 0 &&
		a.Requests.Memory().Cmp(*b.Requests.Memory()) == 0
}

// artifactAPIEqual compares two ArtifactAPI configurations.
func artifactAPIEqual(a, b v1alpha1.ArtifactAPI) bool {
	return a.Endpoint == b.Endpoint &&
		a.Label == b.Label &&
		a.TenantID == b.TenantID &&
		a.Token.SecretRef.Name == b.Token.SecretRef.Name &&
		a.Token.SecretRef.Key == b.Token.SecretRef.Key
}
