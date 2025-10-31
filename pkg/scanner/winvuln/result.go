package winvuln

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/accuknox/accuknox-windows-scanner/pkg/types"
)

type Result struct {
	*types.ScanResult
	VMUri    string `json:"vmURI,omitempty"`
	Platform string `json:"platform,omitempty"`
	OS       string `json:"os,omitempty"`
}

func (r Result) JSON() []byte {
	payload, _ := json.Marshal(r)
	return payload
}

func (r Result) JSONReader() io.Reader {
	buf := bytes.NewBuffer(r.JSON())
	return buf
}

func (r Result) DataType() string {
	return "WINVM"
}
