package clamav

import (
	"github.com/Keyurendra/shadowtest/pkg/scanner/clamav/hash"
	"github.com/Keyurendra/shadowtest/pkg/scanner/clamav/metadata"
	"github.com/Keyurendra/shadowtest/pkg/scanner/clamav/parser"
)

type Result struct {
	Platform        string          `json:"platform,omitempty"`
	VMUri           string          `json:"vmURI,omitempty"`
	OS              string          `json:"os,omitempty"`
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

func (r Result) DataType() string {
	return "CLAMSCAN"
}
