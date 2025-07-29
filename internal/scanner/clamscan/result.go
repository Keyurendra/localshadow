package clamscan

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/accuknox/omniscan/internal/scanner/clamscan/hash"
	"github.com/accuknox/omniscan/internal/scanner/clamscan/metadata"
	"github.com/accuknox/omniscan/internal/scanner/clamscan/parser"
)

type Result struct {
	Platform        string          `json:"platform,omitempty"`
	VMUri           string          `json:"vmURI,omitempty"`
	MaliciousFiles  []MaliciousFile `json:"maliciousFiles"`
	ClamscanSummary parser.Summary  `json:"clamscanSummary"`
	ClamscanErrors  []string        `json:"clamscanErrors,omitempty"`
}

type MaliciousFile struct {
	Path            string             `json:"path"`
	ClamAVSignature string             `json:"clamAVSignature"`
	Entropy         float64            `json:"entropy,omitempty"`
	Metadata        *metadata.Metadata `json:"metadata,omitempty"`
	Hashes          *hash.Hashes       `json:"hashes,omitempty"`
	Errors          []string           `json:"errors,omitempty"`
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
	return "CLAMSCAN"
}
