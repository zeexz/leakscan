package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"leakscan/internal/detector"
)

// SARIF 2.1.0 output format for GitHub Code Scanning / VS Code SARIF Viewer integration.
// Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// sarifReport is the top-level SARIF 2.1.0 document.
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	HelpURI          string             `json:"helpUri,omitempty"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifMessage      `json:"message"`
	Locations []sarifLocation   `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// PrintSARIFReport serializes findings to SARIF 2.1.0 JSON format.
func PrintSARIFReport(w io.Writer, findings []detector.Finding) error {
	// Build unique rule set from findings
	ruleMap := make(map[string]sarifRule)
	for _, f := range findings {
		ruleID := toRuleID(f.Type)
		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = sarifRule{
				ID:               ruleID,
				ShortDescription: sarifMessage{Text: f.Type},
				DefaultConfig:    sarifDefaultConfig{Level: severityToSARIFLevel(f.Severity)},
			}
		}
	}

	var rules []sarifRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	// Build results
	var results []sarifResult
	for _, f := range findings {
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI: extractFilePath(f.Location),
				},
			},
		}

		if lineNum := extractLineNumber(f.Location); lineNum > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: lineNum}
		}

		results = append(results, sarifResult{
			RuleID:    toRuleID(f.Type),
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: fmt.Sprintf("%s: %s [%s]", f.Type, f.Redacted, f.Remediation)},
			Locations: []sarifLocation{loc},
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "leakscan",
						Version:        "2.1.0",
						InformationURI: "https://github.com/zeexz/secret-leak-scanner",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode SARIF report: %w", err)
	}

	return nil
}

// severityToSARIFLevel maps leakscan severity to SARIF level.
func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// toRuleID converts a finding type name to a SARIF-compatible rule ID.
func toRuleID(findingType string) string {
	s := strings.ToLower(findingType)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return "leakscan/" + s
}

// extractFilePath extracts file path from a location string like "path/to/file:42".
func extractFilePath(location string) string {
	// Handle git-style locations: "path:42 (author: ..., date: ...)"
	if idx := strings.Index(location, " ("); idx != -1 {
		location = location[:idx]
	}
	// Handle "path:linenum"
	if idx := strings.LastIndex(location, ":"); idx != -1 {
		return location[:idx]
	}
	return location
}

// extractLineNumber extracts line number from a location string like "path/to/file:42".
func extractLineNumber(location string) int {
	// Handle git-style locations: "path:42 (author: ..., date: ...)"
	if idx := strings.Index(location, " ("); idx != -1 {
		location = location[:idx]
	}
	if idx := strings.LastIndex(location, ":"); idx != -1 {
		if num, err := strconv.Atoi(location[idx+1:]); err == nil {
			return num
		}
	}
	return 0
}
