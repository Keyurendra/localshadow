package scheduler

import (
	"maps"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Keyurendra/shadowtest/api/v1alpha1"
	"github.com/Keyurendra/shadowtest/pkg/resource"
)

// state tracks the state of all scans in a schedule run.
type state struct {
	mu              sync.RWMutex
	queue           []resource.VM
	activeScans     map[string]resource.VM
	scanHistory     map[string]v1alpha1.VMScanRecord
	completedCount  int
	totalCount      int
	admissionSignal chan struct{}
	doneSignal      chan struct{}
}

func newState(totalVMs int) *state {
	return &state{
		activeScans:     make(map[string]resource.VM),
		scanHistory:     make(map[string]v1alpha1.VMScanRecord),
		totalCount:      totalVMs,
		admissionSignal: make(chan struct{}, 1),
		doneSignal:      make(chan struct{}),
	}
}

func (s *state) markActive(scanName string, vm resource.VM) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeScans[scanName] = vm
}

func (s *state) markCompleted(scanName string, vm resource.VM, phase v1alpha1.ScanPhase) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scanHistory[vm.URI] = v1alpha1.VMScanRecord{
		LastScanTime:  metav1.Now(),
		LastScanName:  scanName,
		LastScanPhase: phase,
	}

	delete(s.activeScans, scanName)
	s.completedCount++

	if s.completedCount == s.totalCount {
		close(s.doneSignal)
	}
}

func (s *state) signalAdmission() {
	select {
	case s.admissionSignal <- struct{}{}:
	default:
	}
}

func (s *state) activeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.activeScans)
}

func (s *state) queueLength() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.queue)
}

func (s *state) copyHistory() map[string]v1alpha1.VMScanRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	history := make(map[string]v1alpha1.VMScanRecord, len(s.scanHistory))
	maps.Copy(history, s.scanHistory)
	return history
}

func (s *state) queueVMs(vms []resource.VM) {
	s.queue = make([]resource.VM, len(vms))
	copy(s.queue, vms)
}

func (s *state) dequeueVM() (resource.VM, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.queue) == 0 {
		return resource.VM{}, false
	}

	vm := s.queue[0]
	s.queue = s.queue[1:]

	return vm, true
}
