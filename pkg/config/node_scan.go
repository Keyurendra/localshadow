package config

import (
	"errors"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type NodeScanConfig struct {
	Namespace        string                        `json:"namespace"`
	Image            string                        `json:"image"`
	ImagePullPolicy  corev1.PullPolicy             `json:"imagePullPolicy"`
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	BackoffLimit     *int32                        `json:"backoffLimit"`
	SkipMalwareScan  bool                          `json:"skipMalwareScan"`
	SkipVulnScan     bool                          `json:"skipVulnScan"`
	Repository       Repository                    `json:"repository"`
	NodeSelector     *metav1.LabelSelector         `json:"nodeSelector"`
	Tolerations      []corev1.Toleration           `json:"tolerations"`
	Resources        corev1.ResourceRequirements   `json:"resources"`
	AdditionalEnv    []corev1.EnvVar               `json:"additionalEnv"`
	ArtifactAPI      ArtifactAPIConfig             `json:"artifactAPI"`
}

type Repository struct {
	VulnDB              string `json:"vulnDB"`
	MsrcDB              string `json:"msrcDB"`
	ClamavDB            string `json:"clamavDB"`
	PlainHTTP           bool   `json:"plainHTTP"`
	SkipTLSVerification bool   `json:"skipTLSVerification"`
}

type ArtifactAPIConfig struct {
	Endpoint            string `json:"endpoint"`
	TenantID            int    `json:"tenantID"`
	Label               string `json:"label"`
	TokenSecretName     string `json:"tokenSecretName"`
	SkipTLSVerification bool   `json:"skipTLSVerification"`
}

func Load(path string) (*NodeScanConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg NodeScanConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &cfg, nil
}

func (c *NodeScanConfig) applyDefaults() {
	if c.Namespace == "" {
		c.Namespace = "omni-system"
	}

	if c.Repository.VulnDB == "" {
		c.Repository.VulnDB = "ghcr.io/aquasecurity/trivy-java-db"
	}

	if c.Repository.MsrcDB == "" {
		c.Repository.MsrcDB = "public.ecr.aws/k9v9d5v2/msrc-db"
	}

	if c.Repository.ClamavDB == "" {
		c.Repository.ClamavDB = "public.ecr.aws/k9v9d5v2/clamav-db"
	}

	if c.ArtifactAPI.TokenSecretName == "" {
		c.ArtifactAPI.TokenSecretName = "accuknox-omni-artifact"
	}

	if c.BackoffLimit == nil {
		def := int32(6)
		c.BackoffLimit = &def
	}
}

func (c *NodeScanConfig) Validate() error {
	var errs []error

	if c.Image == "" {
		errs = append(errs, errors.New("dispatcher.image is required"))
	}

	if c.ArtifactAPI.Endpoint == "" {
		errs = append(errs, errors.New("artifactAPI.endpoint is required"))
	}
	if c.ArtifactAPI.TenantID == 0 {
		errs = append(errs, errors.New("artifactAPI.tenantID is required"))
	}
	if c.ArtifactAPI.Label == "" {
		errs = append(errs, errors.New("artifactAPI.label is required"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
