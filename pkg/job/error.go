package job

import "encoding/json"

type ErrorSummaryMap map[string]ErrorSummary

type ErrorSummary struct {
	OS                 string `json:"os,omitempty"`
	OrchestrationError error  `json:"orchestrationError,omitempty"`
	ClamscanError      error  `json:"clamscanError,omitempty"`
	TrivyError         error  `json:"trivyError,omitempty"`
	ArtifactAPIError   error  `json:"artifactAPIError,omitempty"`
}

func (s ErrorSummary) MarshalJSON() ([]byte, error) {
	type Alias ErrorSummary
	type errSummary struct {
		OrchestrationError string `json:"orchestrationError"`
		ClamscanError      string `json:"clamscanError"`
		TrivyError         string `json:"trivyError"`
		ArtifactAPIError   string `json:"artifactAPIError"`
		*Alias
	}
	return json.Marshal(&errSummary{
		OrchestrationError: errorToString(s.OrchestrationError),
		ClamscanError:      errorToString(s.ClamscanError),
		TrivyError:         errorToString(s.TrivyError),
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
