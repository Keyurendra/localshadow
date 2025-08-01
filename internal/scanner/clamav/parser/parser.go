package parser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parser parses ClamAV scan logs
type Parser struct {
	r io.Reader
}

// New returns a new Parser that reads ClamAV scan logs from the provided
// io.Reader.
//
// The scan should have been executed with the following args:
//
//	clamscan -irl /tmpl/clamscan.log /path/to/rootfs
func New(r io.Reader) Parser {
	return Parser{
		r: r,
	}
}

// Parse parses the ClamAV scan logs and returns the scan results.
func (p Parser) Parse() (*Result, error) {
	var result Result

	sep := regexp.MustCompile(`^-+$`)
	sumStart := regexp.MustCompile(`^-+ SCAN SUMMARY -+$`)
	inSum := false
	i := 0

	sc := bufio.NewScanner(p.r)
	for sc.Scan() {
		i++

		ln := strings.TrimSpace(sc.Text())
		if ln == "" || sep.MatchString(ln) {
			continue
		}

		if sumStart.MatchString(ln) {
			// summary section always comes at the very end of the report.
			inSum = true
			continue
		}

		if inSum {
			if !strings.Contains(ln, ":") {
				continue
			}
			parts := strings.SplitN(ln, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])

			switch k {
			case "Known viruses":
				n, err := strconv.ParseUint(v, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("%d: converting %q(=%s) to uint: %w", i, k, v, err)
				}
				result.Summary.KnownViruses = n
			case "Engine version":
				result.Summary.EngineVersion = v
			case "Scanned directories":
				n, err := strconv.ParseUint(v, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("%d: converting %q(=%s) to uint: %w", i, k, v, err)
				}
				result.Summary.ScannedDirectories = n
			case "Scanned files":
				n, err := strconv.ParseUint(v, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("%d: converting %q(=%s) to uint: %w", i, k, v, err)
				}
				result.Summary.ScannedFiles = n
			case "Infected files":
				n, err := strconv.ParseUint(v, 10, 0)
				if err != nil {
					return nil, fmt.Errorf("%d: converting %q(=%s) to uint: %w", i, k, v, err)
				}
				result.Summary.InfectedFiles = n
			case "Data scanned":
				result.Summary.DataScanned = v
			case "Data read":
				parts := strings.SplitN(v, " ", 3)
				result.Summary.DataRead = parts[0] + " " + parts[1]
			case "Start Date":
				t, err := time.Parse("2006:01:02 15:04:05", v)
				if err != nil {
					return nil, fmt.Errorf("%d: parsing time %q(=%s): %w", i, k, v, err)
				}
				result.Summary.StartDate = t
			case "End Date":
				t, err := time.Parse("2006:01:02 15:04:05", v)
				if err != nil {
					return nil, fmt.Errorf("%d: parsing time %q(=%s): %w", i, k, v, err)
				}
				result.Summary.EndDate = t
			}

			continue
		}

		if !strings.Contains(ln, ":") {
			continue
		}

		parts := strings.SplitN(ln, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		if strings.HasPrefix(ln, "ERROR") || strings.HasSuffix(ln, "ERROR") {
			if parts[0] == "ERROR" {
				result.Errors = append(result.Errors, parts[1])
				continue
			}
			result.Errors = append(result.Errors, parts[0])
			continue
		}

		if strings.HasPrefix(ln, "WARNING") || strings.HasSuffix(ln, "WARNING") {
			if parts[0] == "WARNING" {
				result.Errors = append(result.Errors, parts[1])
				continue
			}
			result.Errors = append(result.Errors, parts[0])
			continue
		}

		path := strings.TrimSpace(parts[0])
		status := strings.TrimSpace(parts[1])

		if strings.HasSuffix(status, "FOUND") {
			result.MaliciousFiles = append(result.MaliciousFiles, MaliciousFile{
				Path:      path,
				Signature: strings.TrimSuffix(status, " FOUND"),
			})
		}
	}

	return &result, nil
}
