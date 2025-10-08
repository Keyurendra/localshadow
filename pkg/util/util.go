package util

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Ptr[T any](v T) *T {
	return &v
}

func SplitKubernetesNamespaced(s string) (string, string) {
	if strings.Contains(s, "/") {
		parts := strings.SplitN(s, "/", 2)
		return parts[1], parts[0]
	}
	return s, metav1.NamespaceDefault
}
