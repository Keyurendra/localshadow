package trivy

import (
	"time"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Result struct {
	SchemaVersion int
	CreatedAt     time.Time
	ArtifactName  string
	ArtifactType  string
	Metadata      Metadata
	Results       types.Results
}

type Metadata struct {
	Size        int64
	OS          *ftypes.OS
	VM          VMMetadata
	ImageID     string
	DiffIDs     []string
	RepoTags    []string
	RepoDigests []string
	ImageConfig v1.ConfigFile
	Layers      ftypes.Layers
}

type VMMetadata struct {
	URI      string `json:"uri,omitempty"`
	Platform string `json:"platform,omitempty"`
	OS       string `json:"os,omitempty"`
}

func (r Result) DataType() string {
	return "TR"
}
