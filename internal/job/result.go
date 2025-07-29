package job

import "github.com/accuknox/omniscan/internal/artifact"

type execResult struct {
	OS            string
	Clamscan      artifact.Findings
	Trivy         artifact.Findings
	ClamscanError error
	TrivyError    error
}
