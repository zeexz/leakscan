package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"leakscan/internal/detector"
	"leakscan/rules"
)

func shellTestDetectors(t *testing.T) []detector.Detector {
	t.Helper()
	ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	regexDet, err := detector.NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}
	return []detector.Detector{regexDet}
}

func TestShellHistoryScanner_MissingHistoryFile(t *testing.T) {
	detectors := shellTestDetectors(t)
	scanner := NewShellHistoryScanner(detectors)

	// Should not crash when history files don't exist
	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan should not return error for missing history files: %v", err)
	}
	// Findings may or may not exist depending on the test machine's history.
	// The key assertion is no panic and no error.
	_ = findings
}

func TestShellHistoryScanner_ZshTimestampParsing(t *testing.T) {
	// Test the zsh history line cleaner directly
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    ": 1612345678:0;export API_KEY=secret123",
			expected: "export API_KEY=secret123",
		},
		{
			input:    "normal command",
			expected: "normal command",
		},
		{
			input:    ": 1600000000:0;curl -H 'Authorization: Bearer token123'",
			expected: "curl -H 'Authorization: Bearer token123'",
		},
		{
			input:    "",
			expected: "",
		},
		{
			input:    ": no semicolon here",
			expected: ": no semicolon here",
		},
	}

	for _, tt := range tests {
		got := cleanZshHistoryLine(tt.input)
		if got != tt.expected {
			t.Errorf("cleanZshHistoryLine(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestShellHistoryScanner_DetectsExportedSecret(t *testing.T) {
	// Create a temporary history file
	dir := t.TempDir()
	histFile := filepath.Join(dir, ".test_history")
	content := `ls
cd /tmp
export AWS_ACCESS_KEY_ID=AKIATESTKEY1234567890
echo hello
`
	if err := os.WriteFile(histFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Override HISTFILE to point to our test file
	oldHist := os.Getenv("HISTFILE")
	os.Setenv("HISTFILE", histFile)
	defer os.Setenv("HISTFILE", oldHist)

	detectors := shellTestDetectors(t)
	scanner := NewShellHistoryScanner(detectors)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Should detect the AWS key in the history file
	found := false
	for _, f := range findings {
		if f.Source == "shell_history" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to detect AWS key in shell history")
	}
}

func TestShellHistoryScanner_Name(t *testing.T) {
	scanner := NewShellHistoryScanner(nil)
	if scanner.Name() != "shell_history" {
		t.Errorf("Expected name 'shell_history', got %q", scanner.Name())
	}
}
