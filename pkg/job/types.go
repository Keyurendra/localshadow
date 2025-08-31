package job

import (
	"encoding/json"
	"sync"

	"github.com/accuknox/omniscan/pkg/scanner"
)

type ScheduleConfig struct {
	Crontab               string
	TriggerJobImmediately bool
}

type execResult struct {
	OS            string
	Clamscan      scanner.Findings
	Trivy         scanner.Findings
	ClamscanError error
	TrivyError    error
}

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

type summary struct {
	mu sync.Mutex
	M  map[string]ErrorSummary
}

func newSummary() summary {
	return summary{
		M: make(map[string]ErrorSummary),
	}
}

func (s *summary) Write(uri string, errors ErrorSummary) {
	s.mu.Lock()
	s.M[uri] = errors
	s.mu.Unlock()
}

func (s *summary) Read() map[string]ErrorSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.M
}
