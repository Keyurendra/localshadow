package aiagent

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type executableSignal struct {
	agent Agent
}

type pathSignal struct {
	agent   Agent
	pattern string
}

func Detect(catalog *Catalog, roots []string, packages []PackageSignal) []AgentResult {
	results := make(map[string]*AgentResult)

	// Package detection does not require filesystem traversal.
	for _, agent := range catalog.Agents {
		for _, installation := range agent.Installations {
			for _, packageName := range installation.Signals.Packages {
				for _, installedPackage := range packages {
					if installedPackage.Name != packageName {
						continue
					}

					addPackageDetection(
						results,
						agent,
						installedPackage,
					)
				}
			}
		}
	}

	// Build indexes from the catalog.
	executableSignals := make(map[string][]executableSignal)
	var pathSignals []pathSignal

	for _, agent := range catalog.Agents {
		for _, installation := range agent.Installations {
			for _, executable := range installation.Signals.Executables {
				executableSignals[executable] = append(
					executableSignals[executable],
					executableSignal{
						agent: agent,
					},
				)
			}

			for _, pattern := range installation.Signals.Paths {
				pathSignals = append(
					pathSignals,
					pathSignal{
						agent:   agent,
						pattern: pattern,
					},
				)
			}
		}
	}

	// Track the first path match for each root + pattern.
	// This preserves the behavior of the previous implementation,
	// which stopped path traversal after the first matching directory.
	matchedPaths := make(map[string]bool)

	// Walk each filesystem root only once.
	//
	// Executable detection is intentionally performed only against
	// the supplied filesystem roots. We do not use exec.LookPath()
	// because that would inspect the scanner's PATH rather than the
	// target filesystem being scanned.
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			name := d.Name()

			// Executable detection.
			if signals, ok := executableSignals[name]; ok && !d.IsDir() {
				info, err := d.Info()
				if err == nil && info.Mode()&0111 != 0 {
					for _, signal := range signals {
						addDetection(
							results,
							signal.agent,
							Detection{
								Type:  "executable",
								Value: path,
							},
						)
					}
				}
			}

			// Path detection.
			if d.IsDir() {
				for index, signal := range pathSignals {
					matchKey := filepath.Join(
						root,
						strconv.Itoa(index),
					)

					if matchedPaths[matchKey] {
						continue
					}

					if !matchesPathPattern(path, signal.pattern) {
						continue
					}

					addDetection(
						results,
						signal.agent,
						Detection{
							Type:  "path",
							Value: path,
						},
					)

					matchedPaths[matchKey] = true
				}
			}

			return nil
		})
	}

	output := make([]AgentResult, 0, len(results))

	for _, result := range results {
		output = append(output, *result)
	}

	return output
}

func addPackageDetection(
	results map[string]*AgentResult,
	agent Agent,
	pkg PackageSignal,
) {
	addDetection(
		results,
		agent,
		Detection{
			Type:     "package",
			Value:    pkg.Name,
			Version:  pkg.Version,
			PURL:     pkg.PURL,
			FilePath: pkg.FilePath,
		},
	)
}

func addDetection(
	results map[string]*AgentResult,
	agent Agent,
	detection Detection,
) {
	result, exists := results[agent.ID]

	if !exists {
		result = &AgentResult{
			AgentID:  agent.ID,
			Name:     agent.Name,
			Category: agent.Category,
			Platform: runtime.GOOS,
		}

		results[agent.ID] = result
	}

	for _, existing := range result.Detections {
		if existing.Type != detection.Type {
			continue
		}

		if existing.Value != detection.Value {
			continue
		}

		if existing.Version != detection.Version {
			continue
		}

		if existing.PURL != detection.PURL {
			continue
		}

		if existing.FilePath != detection.FilePath {
			continue
		}

		return
	}

	result.Detections = append(result.Detections, detection)
}

func matchesPathPattern(path, pattern string) bool {
	const prefix = "**/"

	if strings.HasPrefix(pattern, prefix) {
		pattern = strings.TrimPrefix(pattern, prefix)

		normalizedPath := filepath.ToSlash(path)
		pattern = filepath.ToSlash(pattern)

		// Try matching against the complete path.
		if matched, err := filepath.Match(pattern, normalizedPath); err == nil && matched {
			return true
		}

		// For **/, try the pattern at every path boundary.
		parts := strings.Split(
			strings.TrimPrefix(normalizedPath, "/"),
			"/",
		)

		for i := range parts {
			candidate := "/" + strings.Join(parts[i:], "/")

			if matched, err := filepath.Match(
				"/"+pattern,
				candidate,
			); err == nil && matched {
				return true
			}
		}

		return false
	}

	matched, err := filepath.Match(pattern, path)
	return err == nil && matched
}
