package cloud

import (
	"sync"

	"github.com/Keyurendra/shadowtest/pkg/job"
)

type summary struct {
	mu sync.Mutex
	M  job.ErrorSummaryMap
}

func newSummary() summary {
	return summary{
		M: make(job.ErrorSummaryMap),
	}
}

func (s *summary) Write(uri string, errors job.ErrorSummary) {
	s.mu.Lock()
	s.M[uri] = errors
	s.mu.Unlock()
}

func (s *summary) Read() job.ErrorSummaryMap {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.M
}
