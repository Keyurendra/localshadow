package job

import (
	"encoding/json"

	"github.com/accuknox/omniscan/internal/artifact"
)

type execResult struct {
	OS            string
	Clamscan      artifact.Findings
	Trivy         artifact.Findings
	ClamscanError error
	TrivyError    error
}

type ErrorSummary struct {
	OS             string
	ExecutionError error
	ClamscanError  error
	TrivyError     error
}

func (s ErrorSummary) MarshalJSON() ([]byte, error) {
	type Alias ErrorSummary
	type errSummary struct {
		ExecutionError string `json:"executionError"`
		ClamscanError  string `json:"clamscanError"`
		TrivyError     string `json:"trivyError"`
		*Alias
	}
	return json.Marshal(&errSummary{
		ExecutionError: errorToString(s.ExecutionError),
		ClamscanError:  errorToString(s.ClamscanError),
		TrivyError:     errorToString(s.TrivyError),
		Alias:          (*Alias)(&s),
	})
}

func errorToString(err error) string {
	if err != nil {
		return err.Error()
	}
	return "null"
}
