package scheduler

import (
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Keyurendra/shadowtest/api/v1alpha1"
)

func nsFromVMUri(vmURI string) string {
	return strings.Split(vmURI, "/")[0]
}

func nameFromVMUri(vmURI string) string {
	return strings.Split(vmURI, "/")[1]
}

func generateScanName(schedule *v1alpha1.Schedule, vmURI string) string {
	vmName := nameFromVMUri(vmURI)
	vmNS := nsFromVMUri(vmURI)
	timestamp := schedule.Status.LastScheduleTime.Format("20060102150405")
	name := schedule.Name + "-" + vmNS + "-" + vmName + "-" + timestamp
	if len(name) > 63 {
		return name[:63]
	}
	return name
}

// calculateRescanThreshold determines the rescan threshold based on cron
// schedule. Returns 90% of the schedule interval.
func calculateRescanThreshold(cronSchedule string) time.Duration {
	opts := cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor
	parser := cron.NewParser(opts)
	schedule, err := parser.Parse(cronSchedule)
	if err != nil {
		return 24 * time.Hour // fallback
	}
	now := time.Now()
	next1 := schedule.Next(now)
	next2 := schedule.Next(next1)
	interval := next2.Sub(next1)
	threshold := max(time.Duration(float64(interval)*0.9), time.Minute)
	return threshold
}
