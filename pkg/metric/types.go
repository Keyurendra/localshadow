package metric

type ErrorType string

const (
	ErrorTypeVulnScan      ErrorType = "vuln_scan"
	ErrorTypeMalwareScan   ErrorType = "malware_scan"
	ErrorTypeArtifactAPI   ErrorType = "artifact_api"
	ErrorTypeOrchestration ErrorType = "orchestration"
)

func (e ErrorType) String() string {
	return string(e)
}

type ScanType string

const (
	ScanTypeVulnScan    ScanType = "vuln_scan"
	ScanTypeMalwareScan ScanType = "malware_scan"
)

func (s ScanType) String() string {
	return string(s)
}

type OSType string

const (
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"
)

func (o OSType) String() string {
	return string(o)
}
