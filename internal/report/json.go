package report

import (
	"encoding/json"
	"fmt"
	"io"

	"leakscan/internal/detector"
)

// JSONReport represents the structured JSON output format.
type JSONReport struct {
	TotalFindings int                `json:"total_findings"`
	CriticalCount int                `json:"critical_count"`
	HighCount     int                `json:"high_count"`
	MediumCount   int                `json:"medium_count"`
	Findings      []detector.Finding `json:"findings"`
}

// PrintJSONReport serializes findings to JSON output stream.
func PrintJSONReport(w io.Writer, findings []detector.Finding) error {
	report := JSONReport{
		TotalFindings: len(findings),
		Findings:      findings,
	}

	if findings == nil {
		report.Findings = []detector.Finding{}
	}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			report.CriticalCount++
		case "high":
			report.HighCount++
		case "medium":
			report.MediumCount++
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode findings to JSON: %w", err)
	}

	return nil
}
