package config

import (
	"os"
	"path/filepath"
	"testing"

	"leakscan/internal/detector"
)

func TestComputeFingerprint_Stability(t *testing.T) {
	f1 := detector.Finding{
		Type:     "AWS Access Key ID",
		Location: "src/config/keys.go:42",
		Redacted: "AKIA************ABCD",
		Severity: "critical",
	}

	// Same finding, shifted to line 99
	f2 := detector.Finding{
		Type:     "AWS Access Key ID",
		Location: "src/config/keys.go:99 (author: dev@example.com)",
		Redacted: "AKIA************ABCD",
		Severity: "critical",
	}

	fp1 := ComputeFingerprint(f1)
	fp2 := ComputeFingerprint(f2)

	if fp1 != fp2 {
		t.Errorf("Fingerprints should match despite line number or author shift, got %s vs %s", fp1, fp2)
	}

	// Different secret
	f3 := detector.Finding{
		Type:     "AWS Access Key ID",
		Location: "src/config/keys.go:42",
		Redacted: "AKIA************WXYZ",
		Severity: "critical",
	}
	fp3 := ComputeFingerprint(f3)
	if fp1 == fp3 {
		t.Errorf("Different secrets must produce different fingerprints")
	}
}

func TestSaveAndLoadBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, ".leakscan-baseline.json")

	sampleFindings := []detector.Finding{
		{
			Type:     "AWS Access Key ID",
			Location: "pkg/auth/aws.go:12",
			Redacted: "AKIA************ABCD",
			Severity: "critical",
		},
		{
			Type:     "Slack Webhook URL",
			Location: "pkg/notify/slack.go:55",
			Redacted: "https://hooks.slack.com/services/T00***/***",
			Severity: "high",
		},
	}

	// 1. Save
	if err := SaveBaseline(baselinePath, sampleFindings); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("Baseline file was not created: %v", err)
	}

	// 2. Load
	b, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}

	if b.TotalFindings != 2 {
		t.Errorf("expected 2 total findings in baseline, got %d", b.TotalFindings)
	}

	// 3. Test Suppression
	if !b.IsSuppressed(sampleFindings[0]) {
		t.Errorf("expected sampleFindings[0] to be suppressed by baseline")
	}

	newFinding := detector.Finding{
		Type:     "Stripe API Key",
		Location: "pkg/billing/stripe.go:8",
		Redacted: "sk_live_************",
		Severity: "critical",
	}
	if b.IsSuppressed(newFinding) {
		t.Errorf("new finding should NOT be suppressed by baseline")
	}

	// 4. Test FilterAgainstBaseline
	allFindings := append(sampleFindings, newFinding)
	active, suppressed := FilterAgainstBaseline(allFindings, b)

	if len(active) != 1 || active[0].Type != "Stripe API Key" {
		t.Errorf("expected 1 active finding (Stripe API Key), got %d", len(active))
	}

	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed findings, got %d", len(suppressed))
	}
}
