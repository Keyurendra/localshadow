package job

import (
	"encoding/json"
	"sync"

	"github.com/accuknox/omniscan/pkg/scanner"
)

type execResult struct {
	OS            string
	Clamscan      scanner.Findings
	Trivy         scanner.Findings
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
