//go:build windows

package winvuln

import "github.com/accuknox/accuknox-windows-scanner/pkg/types"

type Result struct {
	*types.ScanResult
	VMUri    string `json:"vmURI,omitempty"`
	Platform string `json:"platform,omitempty"`
	OS       string `json:"os,omitempty"`
}

func (r Result) DataType() string {
	return "WINVM"
}
