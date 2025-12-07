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
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScheduleSpec defines the desired state of Schedule
type ScheduleSpec struct {
	// Template defines the template used for scheduled scans.
	// +required
	Template ScheduleTemplate `json:"template"`
	// CronJobNamespace defines the namespace in which the Kubernetes CronJob
	// must be created.
	// +required
	CronJobNamespace string `json:"cronJobNamespace"`
	// Concurrency defines the no. of scans to run concurrently.
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Concurrency int32 `json:"concurrency,omitzero"`
	// Schedule in Cron format, see https://en.wikipedia.org/wiki/Cron.
	// +kubebuilder:validation:MinLength=1
	// +required
	Schedule string `json:"schedule"`
	// The time zone name for the given schedule, see
	// https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.
	// If not specified, this will default to the time zone of the
	// kube-controller-manager process. The set of valid time zone names and
	// the time zone offset is loaded from the system-wide time zone database
	// by the API server during CronJob validation and the controller manager
	// during execution. If no system-wide time zone database can be found a
	// bundled version of the database is used instead. If the time zone name
	// becomes invalid during the lifetime of a CronJob or due to a change in
	// host configuration, the controller will stop creating new new Jobs and
	// will create a system event with the reason UnknownTimeZone.
	// More information can be found in
	// https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#time-zones
	// +optional
	TimeZone *string `json:"timeZone"`
	// The number of finished scans to retain. Value must be non-negative
	// integer. Defaults to 3.
	// +kubebuilder:default:=3
	// +optional
	ScansHistoryLimit *int32 `json:"scansHistoryLimit"`
	// NamespaceSelector restricts scans to specific namespaces. This
	// unrelated to CronJobNamespace.
	// +optional
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
	// VMSelector is a label query over VMs.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
	// +optional
	VMSelector *metav1.LabelSelector `json:"vmSelector,omitempty"`
	// AccuKnox Artifact API configuration. Resulting scan artifacts are
	// published to this endpoint.
	ArtifactAPI ArtifactAPI `json:"artifactAPI"`
}

// ScheduleTemplate defines a scan template embedded in a Schedule.
type ScheduleTemplate struct {
	// Metadata carries standard object metadata for the scan.
	// +optional
	Metadata *metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec defines the scan specification.
	// +required
	Spec ScheduleTemplateSpec `json:"spec"`
}

type ScheduleTemplateSpec struct {
	// Unique identifier for your cluster. This name will be used as the asset
	// name for scan findings on the AccuKnox platform.
	// +kubebuilder:validation:MinLength=1
	// +required
	ClusterName string `json:"clusterName"`
	// Skip malware scanning. Malware scanning can be CPU intensive. Disabled
	// by default.
	// +kubebuilder:default:=true
	// +optional
	SkipMalwareScan *bool `json:"skipMalwareScan"`
	// Image is the container image to use.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	// +optional
	Image string `json:"image,omitempty"`
	// ImagePullPolicy defines how the image is pulled.
	// One of Always, Never, IfNotPresent.
	// Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
	// +kubebuilder:validation:Enum=Always;Never;IfNotPresent
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// BackoffLimit is the number of retries before marking the job failed.
	// Defaults to 6.
	// +kubebuilder:default:=6
	// +optional
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`
	// Resources specifies compute resources required by the container.
	// More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`
}

// NamespaceSelectorOperator represents valid namespace selection operators.
type NamespaceSelectorOperator string

const (
	NamespaceSelectorOpIn    NamespaceSelectorOperator = "In"
	NamespaceSelectorOpNotIn NamespaceSelectorOperator = "NotIn"
)

// NamespaceSelector restricts scans to namespaces based on label matching.
type NamespaceSelector struct {
	// Operator represents a key's relationship to a set of values.
	// Valid operators are In, NotIn.
	// +kubebuilder:validation:Enum=In;NotIn
	// +required
	Operator NamespaceSelectorOperator `json:"operator,omitempty"`
	// Values is an array of string values.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:Items:MinLength=1
	// +required
	Values []string `json:"values,omitempty"`
}

// ScheduleStatus defines the observed state of Schedule.
type ScheduleStatus struct {
	// Phase represents the current phase of the scan.
	// +kubebuilder:validation:Enum=Unknown;Bootstrapping;BootstrapFailed;Awaiting;Running
	// +kubebuilder:default:=Bootstrapping
	Phase SchedulePhase `json:"phase,omitempty"`
	// LastScheduleTime is the last time a scheduled scan run was triggered.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`
	// LastSuccessfulTime is the last time a scheduled scan run completed
	// successfully.
	// +optional
	LastSuccessfulTime *metav1.Time `json:"lastSuccessfulTime,omitempty"`
	// ActiveScans tracks currently running scans from the last schedule
	// execution.
	// +optional
	ActiveScans int32 `json:"activeScans,omitempty"`
	// VMScanHistory tracks the last scan time for each VM to avoid
	// re-scanning recently scanned VMs.
	// Map key format: "namespace/vmName"
	// +optional
	VMScanHistory map[string]VMScanRecord `json:"vmScanHistory,omitempty"`
}

// VMScanRecord tracks scan history for a specific VM.
type VMScanRecord struct {
	// LastScanTime is when the VM was last scanned.
	LastScanTime metav1.Time `json:"lastScanTime"`
	// LastScanName is the name of the last scan resource created for this VM.
	LastScanName string `json:"lastScanName"`
	// LastScanPhase is the phase of the last scan.
	// +kubebuilder:validation:Enum=Unknown;Pending;Running;Succeeded;Failed
	LastScanPhase ScanPhase `json:"lastScanPhase"`
}

// SchedulePhase represents lifecycle phases of a scheduled scan.
type SchedulePhase string

const (
	SchedulePhaseUnknown         SchedulePhase = "Unknown"
	SchedulePhaseBootstrapping   SchedulePhase = "Bootstrapping"
	SchedulePhaseBootstrapFailed SchedulePhase = "BootstrapFailed"
	SchedulePhaseAwaiting        SchedulePhase = "Awaiting"
	SchedulePhaseRunning         SchedulePhase = "Running"
)

// Schedule is the Schema for the schedules API
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`,description="Cron expression for scan execution"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`,description="Current phase of the schedule"
// +kubebuilder:printcolumn:name="Last Schedule",type=date,JSONPath=`.status.lastScheduleTime`,description="Last time a scan was triggered"
// +kubebuilder:printcolumn:name="Active Scans",type=integer,JSONPath=`.status.activeScans`,description="Currently running scans"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="Time since creation"
type Schedule struct {
	metav1.TypeMeta `json:",inline"`
	// Metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata"`
	// Spec defines the desired state of Schedule
	// +required
	Spec ScheduleSpec `json:"spec"`
	// Status defines the observed state of Schedule
	// +optional
	Status ScheduleStatus `json:"status"`
}

// ScheduleList contains a list of Schedule
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Schedule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Schedule{}, &ScheduleList{})
}

// Hash returns an 8-character hash of the Schedule spec.
func (s Schedule) Hash() (string, error) {
	byts, err := json.Marshal(s.Spec)
	if err != nil {
		return "", fmt.Errorf("marshaling Schedule CR %s/%s to json: %w", s.Namespace, s.Name, err)
	}
	h := sha1.New()
	h.Write(byts)
	return hex.EncodeToString(h.Sum(nil))[:8], nil
}
