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

// ScanSpec defines the desired state of Scan
type ScanSpec struct {
	// Unique identifier for your cluster. This name will be used as the asset
	// name for scan findings on the AccuKnox platform.
	// +kubebuilder:validation:MinLength=1
	// +required
	ClusterName string `json:"clusterName"`
	// VirtualMachineName is the name of the virtual machine to be scanned.
	// +kubebuilder:validation:MinLength=1
	// +required
	VirtualMachineName string `json:"virtualMachineName"`
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
	// AccuKnox Artifact API configuration. Resulting scan artifacts are
	// published to this endpoint.
	ArtifactAPI ArtifactAPI `json:"artifactAPI"`
}

// ArtifactAPI defines configuration for publish the resulting scan artifacts.
type ArtifactAPI struct {
	// AccuKnox artifact api endpoint.
	// +required
	Endpoint string `json:"endpoint"`
	// Label to be assosciated with the resulting scan findings.
	// +required
	Label string `json:"label"`
	// AccuKnox platform tenancy ID
	// +required
	TenantID uint `json:"tenantID"`
	// JWT auth token for the artifact API.
	// +required
	Token ArtifactAPIToken `json:"token"`
}

// ArtifactAPIToken references the JWT auth token for the artifact API.
type ArtifactAPIToken struct {
	// Reference to the Secret containing the token.
	// +required
	SecretRef SecretRef `json:"secretRef"`
}

// SecretRef is the reference to the JWT auth token Secret.
type SecretRef struct {
	// Name of the referent Secret.
	// +required
	Name string `json:"name"`
	// Key within the Secret to select.
	// +required
	Key string `json:"key"`
}

// ScanStatus defines the observed state of Scan.
type ScanStatus struct {
	// StartTime is the time at which the scan started.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// CompletionTime is the time at which the scan completed.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// Phase represents the current phase of the scan.
	// +kubebuilder:default:=Pending
	// +kubebuilder:validation:Enum=Unknown;Pending;Running;Succeeded;Failed
	Phase ScanPhase `json:"phase,omitempty"`
	// IdentifiedOS is the operating system identified by the scanner.
	// +kubebuilder:validation:Enum=Unidentifiable;Linux;Windows
	// +optional
	IdentifiedOS OSType `json:"identifiedOS,omitempty"`
	// Errors are a list of errors returned by the scanner on (partial) failure.
	// +optional
	Errors []ScanError `json:"errors,omitempty"`
	// Conditions represent the latest observations of the scan's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=atomic
	Conditions []ScanCondition `json:"conditions,omitempty"`
}

// ScanPhase represents the lifecycle phase of a scan.
type ScanPhase string

const (
	ScanPhaseUnknown   ScanPhase = "Unknown"
	ScanPhasePending   ScanPhase = "Pending"
	ScanPhaseRunning   ScanPhase = "Running"
	ScanPhaseSucceeded ScanPhase = "Succeeded"
	ScanPhaseFailed    ScanPhase = "Failed"
)

// ScanCondition describes a condition of a scan.
type ScanCondition struct {
	// Type of scan condition.
	// +required
	Type ScanConditionType `json:"type"`
	// Status of the condition.
	// +kubebuilder:default:=Unknown
	// +kubebuilder:validation:Enum=Unknown;True;False
	Status corev1.ConditionStatus `json:"status"`
	// Last time the condition was checked.
	// +optional
	LastProbeTime metav1.Time `json:"lastProbeTime,omitzero"`
	// Last time the condition transit from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitzero"`
	// (brief) reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Human readable message indicating details about last transition.
	// +optional
	Message string `json:"message,omitempty"`
}

// ScanConditionType represents condition types for Scan.
type ScanConditionType string

const (
	ScanConditionOrchestrationJobCreated  ScanConditionType = "OrchestrationJobCreated"
	ScanConditionOrchestrationJobFinished ScanConditionType = "OrchestrationJobFinished"
	ScanConditionSnapshotTaken            ScanConditionType = "SnapshotTaken"
	ScanConditionClonedPVCReady           ScanConditionType = "ClonedPVCReady"
	ScanConditionScanJobCreated           ScanConditionType = "ScanJobCreated"
	ScanConditionScanJobFinished          ScanConditionType = "ScanJobFinished"
	ScanConditionVulnScanCompleted        ScanConditionType = "VulnScanCompleted"
	ScanConditionMalwareScanCompleted     ScanConditionType = "MalwareScanCompleted"
	ScanConditionArtifactPublished        ScanConditionType = "ArtifactPublished"
)

// OSType represents operating systems.
type OSType string

const (
	OSUnidentifiable OSType = "Unidentifiable"
	OSLinux          OSType = "Linux"
	OSWindows        OSType = "Windows"
)

// ScanError represents an error encountered during scanning.
type ScanError struct {
	// Type is the category of the error.
	// +kubebuilder:validation:Enum=Orchestration;VulnScan;MalwareScan;ArtifactAPI
	Type ErrorType `json:"type"`
	// Message provides details about the error.
	Message string `json:"message"`
}

// ErrorType categorizes scanner errors.
type ErrorType string

const (
	ErrorOrchestration ErrorType = "Orchestration"
	ErrorVulnScan      ErrorType = "VulnScan"
	ErrorMalwareScan   ErrorType = "MalwareScan"
	ErrorArtifactAPI   ErrorType = "ArtifactAPI"
)

// Scan is the Schema for the scans API
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="VM",type=string,JSONPath=`.spec.virtualMachineName`,description="Virtual machine being scanned"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`,description="Current phase of the scan"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="Time since creation"
type Scan struct {
	metav1.TypeMeta `json:",inline"`
	// Metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata"`
	// Spec defines the desired state of Scan
	// +required
	Spec ScanSpec `json:"spec"`
	// Status defines the observed state of Scan
	// +optional
	Status ScanStatus `json:"status"`
}

// GetCondition returns the condition for the given type if it exists.
func (s *ScanStatus) GetCondition(t ScanConditionType) *ScanCondition {
	for i := range s.Conditions {
		if s.Conditions[i].Type == t {
			return &s.Conditions[i]
		}
	}
	return nil
}

// SetCondition updates or creates a condition.
func (s *ScanStatus) SetCondition(c ScanCondition) {
	now := metav1.Now()
	current := s.GetCondition(c.Type)
	if current == nil {
		c.LastTransitionTime = now
		c.LastProbeTime = now
		s.Conditions = append(s.Conditions, c)
		return
	}
	c.LastProbeTime = now
	c.LastTransitionTime = current.LastTransitionTime
	if current.Status != c.Status {
		c.LastTransitionTime = now
	}
	*current = c
}

// RemoveCondition removes the condition of the given type.
func (s *ScanStatus) RemoveCondition(t ScanConditionType) {
	var conditions []ScanCondition
	for _, cond := range s.Conditions {
		if cond.Type != t {
			conditions = append(conditions, cond)
		}
	}
	s.Conditions = conditions
}

// ScanList contains a list of Scan
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Scan `json:"items"`
}

func init() {
}

// Hash returns an 8-character hash of the Scan spec.
func (s Scan) Hash() (string, error) {
	byts, err := json.Marshal(s.Spec)
	if err != nil {
		return "", fmt.Errorf("marshaling Scan CR %s/%s to json: %w", s.Namespace, s.Name, err)
	}
	h := sha1.New()
	h.Write(byts)
	return hex.EncodeToString(h.Sum(nil))[:8], nil
}
