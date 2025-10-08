package openshift

import kubevirtv1 "kubevirt.io/api/core/v1"

func findBootDisk(disks []kubevirtv1.Disk) *kubevirtv1.Disk {
	if len(disks) == 0 {
		return nil
	}
	var ordered []*kubevirtv1.Disk
	for _, disk := range disks {
		if disk.BootOrder == nil {
			ordered = append(ordered, &disk)
			continue
		}
		if *disk.BootOrder == 1 {
			return &disk
		}
	}
	return ordered[0]
}
