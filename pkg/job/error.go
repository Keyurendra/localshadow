package job

import "encoding/json"

type ErrorSummaryMap map[string]ErrorSummary

type ErrorSummary struct {
	OS                 string `json:"os,omitempty"`
	OrchestrationError error  `json:"orchestrationError,omitempty"`
	MalwareScanError   error  `json:"malwareScanError,omitempty"`
	VulnScanError      error  `json:"vulnScanError,omitempty"`
	ArtifactAPIError   error  `json:"artifactAPIError,omitempty"`
}

func (s ErrorSummary) MarshalJSON() ([]byte, error) {
	type Alias ErrorSummary
	type errSummary struct {
		OrchestrationError string `json:"orchestrationError"`
		MalwareScanError   string `json:"malwareScanError"`
		VulnScanError      string `json:"vulnScanError"`
		ArtifactAPIError   string `json:"artifactAPIError"`
		*Alias
	}
	return json.Marshal(&errSummary{
		OrchestrationError: errorToString(s.OrchestrationError),
		MalwareScanError:   errorToString(s.MalwareScanError),
		VulnScanError:      errorToString(s.VulnScanError),
		ArtifactAPIError:   errorToString(s.ArtifactAPIError),
		Alias:              (*Alias)(&s),
	})
}

func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return "null"
}
