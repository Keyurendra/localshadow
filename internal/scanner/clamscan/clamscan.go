package clamscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/accuknox/omniscan/internal/artifact"
	"github.com/accuknox/omniscan/internal/scanner/clamscan/parser.go"
)

func Scan(ctx context.Context, mountpoint, vmURI, platform string) (artifact.Findings, error) {
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

	result, err := parser.New(buf).Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing clamscan output: %w", err)
	}

	for idx, file := range result.MaliciousFiles {
		result.MaliciousFiles[idx].Path = strings.TrimPrefix(file.Path, mountpoint)
	}

	result.VMUri = vmURI
	result.Platform = platform

	return result, nil
}
