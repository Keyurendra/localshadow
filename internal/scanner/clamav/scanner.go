package clamav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/accuknox/omniscan/internal/scanner/clamav/entropy"
	"github.com/accuknox/omniscan/internal/scanner/clamav/hash"
	"github.com/accuknox/omniscan/internal/scanner/clamav/metadata"
	"github.com/accuknox/omniscan/internal/scanner/clamav/parser"
	"github.com/accuknox/omniscan/pkg/scanner"
)

type s struct{}

func NewScanner() scanner.Scanner {
	return s{}
}

func (s) Scan(ctx context.Context, mountpoint, vmURI, platform string) (scanner.Findings, error) {
	path, err := exec.LookPath("clamscan")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("`clamscan` executable not found in PATH")
		}
		return nil, fmt.Errorf("looking up clamscan in PATH: %w", err)
	}

	var stderr, stdout bytes.Buffer

	cmd := exec.CommandContext(
		ctx,
		path,
		mountpoint,
		"--infected",
		"--recursive",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	buf := new(bytes.Buffer)
	if _, err := stderr.WriteTo(buf); err != nil {
		return nil, fmt.Errorf("writing stderr to buffer: %w", err)
	}
	if _, err := stdout.WriteTo(buf); err != nil {
		return nil, fmt.Errorf("writing stdout to buffer: %w", err)
	}

	parsed, err := parser.New(buf).Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing clamscan output: %w", err)
	}

	enriched := Result{
		Platform:        platform,
		VMUri:           vmURI,
		MaliciousFiles:  make([]MaliciousFile, len(parsed.MaliciousFiles)),
		ClamscanSummary: parsed.Summary,
		ClamscanErrors:  parsed.Errors,
	}

	for idx, file := range parsed.MaliciousFiles {
		mal := MaliciousFile{
			Path:            strings.TrimPrefix(file.Path, mountpoint),
			ClamAVSignature: file.Signature,
		}

		f, err := os.Open(file.Path)
		if err != nil {
			mal.Errors = append(
				mal.Errors,
				fmt.Sprintf("opening file: %s", err.Error()),
			)
			enriched.MaliciousFiles[idx] = mal
			continue
		}

		f.Seek(0, io.SeekStart)
		mal.Hashes, err = hash.Calculate(f)
		if err != nil {
			mal.Errors = append(
				mal.Errors,
				fmt.Sprintf("calculating hashes: %s", err.Error()),
			)
		}

		f.Seek(0, io.SeekStart)
		mal.Metadata, err = metadata.Collect(f)
		if err != nil {
			mal.Errors = append(
				mal.Errors,
				fmt.Sprintf("collecting metadata: %s", err.Error()),
			)
		}

		f.Seek(0, io.SeekStart)
		mal.Entropy, err = entropy.Calculate(f)
		if err != nil {
			mal.Errors = append(
				mal.Errors,
				fmt.Sprintf("calculating Shanon entropy: %s", err.Error()),
			)
		}

		f.Close()
		enriched.MaliciousFiles[idx] = mal
	}

	return enriched, nil
}
