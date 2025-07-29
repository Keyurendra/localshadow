package parser

import (
	"time"
)

type Result struct {
	Errors         []string        `json:"errors,omitempty"`
	MaliciousFiles []MaliciousFile `json:"maliciousFiles"`
	Summary        Summary         `json:"summary"`
}

type MaliciousFile struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
}

type Summary struct {
	KnownViruses       uint64    `json:"knownViruses,omitempty"`
	EngineVersion      string    `json:"engineVersion,omitempty"`
	ScannedDirectories uint64    `json:"scannedDirectories,omitempty"`
	ScannedFiles       uint64    `json:"scannedFiles,omitempty"`
	InfectedFiles      uint64    `json:"infectedFiles,omitempty"`
	DataScanned        string    `json:"dataScanned,omitempty"`
	DataRead           string    `json:"dataRead,omitempty"`
	StartDate          time.Time `json:"startDate"`
	EndDate            time.Time `json:"endDate"`
}
