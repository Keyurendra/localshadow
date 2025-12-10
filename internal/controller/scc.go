package controller

import (
	"context"
	"fmt"
	"slices"

	securityv1 "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	sccName = "omniscan-privileged"
)

func (r *ScanReconciler) isOpenShift() bool {
	sccGVR := schema.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextconstraints",
	}
	discoveryClient := r.KubeClient.Discovery()
	gv := sccGVR.GroupVersion().String()
	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(gv)
	if err != nil {
		return false
	}
	for _, resource := range apiResourceList.APIResources {
		if resource.Name == "securitycontextconstraints" {
			return true
		}
	}
	return false
}

// ensureSCC creates the SCC for scan workloads if running on OpenShift
func (r *ScanReconciler) ensureSCC(ctx context.Context, sa *corev1.ServiceAccount, typ int) error {
	if typ != jobTypeScan || !r.isOpenShift() {
		return nil
	}

	userRef := fmt.Sprintf("system:serviceaccount:%s:%s", sa.Namespace, sa.Name)
	scc := &securityv1.SecurityContextConstraints{}
	key := types.NamespacedName{Name: sccName}

	if err := r.Get(ctx, key, scc); err != nil {
		if !apierr.IsNotFound(err) {
			return fmt.Errorf("get scc: %w", err)
		}
		scc = r.buildSCC()
		scc.Users = []string{userRef}
		err := r.Create(ctx, scc)
		if err == nil {
			return nil
		}
		if !apierr.IsAlreadyExists(err) {
			return fmt.Errorf("create scc: %w", err)
		}
		if err := r.Get(ctx, key, scc); err != nil {
			return fmt.Errorf("get newly created scc: %w", err)
		}
	}

	patch := client.MergeFrom(scc.DeepCopy())
	userExists := slices.Contains(scc.Users, userRef)
	if !userExists {
		scc.Users = append(scc.Users, userRef)
		if err := r.Patch(ctx, scc, patch); err != nil {
			return fmt.Errorf("patch scc: %w", err)
		}
	}

	return nil
}

// buildSCC constructs the SecurityContextConstraints for scan workloads
func (r *ScanReconciler) buildSCC() *securityv1.SecurityContextConstraints {
	allowPrivilegedContainer := true
	allowHostDirVolumePlugin := false
	allowHostIPC := false
	allowHostNetwork := false
	allowHostPID := false
	allowHostPorts := false
	readOnlyRootFilesystem := false

	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: sccName,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "omni-operator",
			},
		},
		AllowPrivilegedContainer: allowPrivilegedContainer,
		AllowHostDirVolumePlugin: allowHostDirVolumePlugin,
		AllowHostIPC:             allowHostIPC,
		AllowHostNetwork:         allowHostNetwork,
		AllowHostPID:             allowHostPID,
		AllowHostPorts:           allowHostPorts,
		ReadOnlyRootFilesystem:   readOnlyRootFilesystem,
		Priority:                 nil,
		RequiredDropCapabilities: []corev1.Capability{},
		AllowedCapabilities: []corev1.Capability{
			"SYS_ADMIN",
			"MKNOD",
		},
		DefaultAddCapabilities: []corev1.Capability{},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyRunAsAny,
		},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyRunAsAny,
		},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyRunAsAny,
		},
		Volumes: []securityv1.FSType{
			securityv1.FSTypeSecret,
			securityv1.FSTypePersistentVolumeClaim,
			securityv1.FSTypeConfigMap,
		},
	}
}

// cleanupSCCUser removes the service account from the SCC when scan is deleted
func (r *ScanReconciler) cleanupSCCUser(ctx context.Context, sa *corev1.ServiceAccount) error {
	if !r.isOpenShift() {
		return nil
	}

	scc := &securityv1.SecurityContextConstraints{}
	key := types.NamespacedName{Name: sccName}

	if err := r.Get(ctx, key, scc); err != nil {
		if apierr.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get scc: %w", err)
	}

	userRef := fmt.Sprintf("system:serviceaccount:%s:%s", sa.Namespace, sa.Name)
	patch := client.MergeFrom(scc.DeepCopy())
	newUsers := []string{}
	for _, user := range scc.Users {
		if user != userRef {
			newUsers = append(newUsers, user)
		}
	}

	if len(newUsers) != len(scc.Users) {
		scc.Users = newUsers
		if err := r.Patch(ctx, scc, patch); err != nil {
			return fmt.Errorf("patch scc to remove user: %w", err)
		}
	}

	return nil
}
