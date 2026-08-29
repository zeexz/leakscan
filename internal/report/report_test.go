package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"leakscan/internal/detector"
)

func TestPrintJSONReport(t *testing.T) {
	findings := []detector.Finding{
		{
			Source:      "file:.env",
			Type:        "AWS Access Key ID",
			Location:    ".env:1",
			Severity:    "critical",
			Redacted:    "AKIA************MPLE",
			Remediation: "Rotate AWS keys",
		},
		{
			Source:      "file:config.yaml",
			Type:        "Slack API Token",
			Location:    "config.yaml:12",
			Severity:    "high",
			Redacted:    "xoxb-********1234",
			Remediation: "Revoke token",
		},
		{
			Source:      "file:notes.txt",
			Type:        "Generic Secret",
			Location:    "notes.txt:5",
			Severity:    "medium",
			Redacted:    "secr********word",
			Remediation: "Remove secret",
		},
	}

	var buf bytes.Buffer
	err := PrintJSONReport(&buf, findings)
	if err != nil {
		t.Fatalf("PrintJSONReport failed: %v", err)
	}

	var parsed JSONReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON report output: %v", err)
	}

	if parsed.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", parsed.TotalFindings)
	}
	if parsed.CriticalCount != 1 {
		t.Errorf("Expected 1 critical finding, got %d", parsed.CriticalCount)
	}
	if parsed.HighCount != 1 {
		t.Errorf("Expected 1 high finding, got %d", parsed.HighCount)
	}
	if parsed.MediumCount != 1 {
		t.Errorf("Expected 1 medium finding, got %d", parsed.MediumCount)
	}
}

func TestPrintSARIFReport(t *testing.T) {
	findings := []detector.Finding{
		{
			Source:      "file:src/auth.go",
			Type:        "GitHub Personal Access Token",
			Location:    "src/auth.go:42",
			Severity:    "critical",
			Redacted:    "ghp_************************wxyz",
			Remediation: "Revoke in GitHub",
		},
		{
			Source:      "git:repo@abcd1234",
			Type:        "Stripe Live Key",
			Location:    "stripe.js:10 (author: Dev <dev@example.com>, date: 2026-01-01)",
			Severity:    "high",
			Redacted:    "sk_live_********************1234",
			Remediation: "Revoke in Stripe",
		},
	}

	var buf bytes.Buffer
	err := PrintSARIFReport(&buf, findings)
	if err != nil {
		t.Fatalf("PrintSARIFReport failed: %v", err)
	}

	var sarif sarifReport
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Failed to parse SARIF output: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(sarif.Runs[0].Results))
	}

	res1 := sarif.Runs[0].Results[0]
	if res1.Level != "error" {
		t.Errorf("Expected error level for critical finding, got %s", res1.Level)
	}
	if res1.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/auth.go" {
		t.Errorf("Expected URI 'src/auth.go', got %s", res1.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if res1.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("Expected start line 42, got %d", res1.Locations[0].PhysicalLocation.Region.StartLine)
	}
}

func TestPrintTerminalReport(t *testing.T) {
	findings := []detector.Finding{
		{
			Source:      "file:.env",
			Type:        "AWS Access Key ID",
			Location:    ".env:1",
			Severity:    "critical",
			Redacted:    "AKIA************MPLE",
			Remediation: "Rotate AWS keys",
		},
	}

	var buf bytes.Buffer
	PrintTerminalReport(&buf, findings)
	out := buf.String()

	if !strings.Contains(out, "LEAKSCAN") {
		t.Errorf("Terminal report missing banner")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("Terminal report missing CRITICAL badge")
	}

	// Test clean report
	buf.Reset()
	PrintTerminalReport(&buf, nil)
	cleanOut := buf.String()
	if !strings.Contains(cleanOut, "CLEAN") {
		t.Errorf("Terminal report missing clean status for zero findings")
	}
}
