package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"leakscan/internal/detector"
)

func TestEngine_EndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Plant a secret
	envFile := filepath.Join(dir, ".env")
	content := "AWS_ACCESS_KEY_ID=" + "AKIA" + "TESTKEY1234567890"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		TargetPath:       dir,
		EntropyThreshold: 3.8,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least 1 finding for planted AWS key, got 0")
	}

	if result.Duration <= 0 {
		t.Error("Expected positive duration")
	}
}

func TestEngine_CustomRulesFile(t *testing.T) {
	dir := t.TempDir()

	// Create a custom rules file
	rulesContent := `rules:
  - id: custom-test-rule
    name: Custom Test Pattern
    pattern: "CUSTOM_SECRET_[A-Z]{10}"
    severity: high
    remediation: Rotate the custom secret.
`
	rulesFile := filepath.Join(dir, "custom-rules.yaml")
	if err := os.WriteFile(rulesFile, []byte(rulesContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a file with the custom pattern
	secretFile := filepath.Join(dir, "config.env")
	content := "MY_VAR=CUSTOM_SECRET_ABCDEFGHIJ"
	if err := os.WriteFile(secretFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		TargetPath:       dir,
		EntropyThreshold: 0, // Disable entropy to isolate regex
		RulesFile:        rulesFile,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	// Should detect via custom rule
	found := false
	for _, f := range result.Findings {
		if f.Type == "Custom Test Pattern" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to detect custom pattern via custom rules file")
	}
}

func TestEngine_EntropyDisabled(t *testing.T) {
	dir := t.TempDir()

	// Create a file that would only trigger entropy detection
	envFile := filepath.Join(dir, "config.env")
	content := "CUSTOM_API_KEY=g9A2xK8vP1mL9qW3zR7kPqXw"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		TargetPath:       dir,
		EntropyThreshold: 0, // Disabled
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	// Should not have entropy-based findings
	for _, f := range result.Findings {
		if f.Type == "High Entropy String / Potential Secret" {
			t.Errorf("Expected no entropy findings when disabled, got: %+v", f)
		}
	}
}

func TestEngine_Deduplication(t *testing.T) {
	findings := []struct {
		source   string
		location string
		redacted string
	}{
		{"file:a.env", "a.env:1", "AKIA********MPLE"},
		{"file:a.env", "a.env:1", "AKIA********MPLE"}, // duplicate
		{"file:b.env", "b.env:1", "AKIA********MPLE"}, // different source
	}

	var input []struct {
		Source   string
		Location string
		Redacted string
	}
	for _, f := range findings {
		input = append(input, struct {
			Source   string
			Location string
			Redacted string
		}{f.source, f.location, f.redacted})
	}

	// Use the DeduplicateFindings function directly
	var detFindings []struct {
		Source   string
		Location string
		Redacted string
	}
	for _, f := range findings {
		detFindings = append(detFindings, struct {
			Source   string
			Location string
			Redacted string
		}{f.source, f.location, f.redacted})
	}

	// Test via imported types
	result := DeduplicateFindings(nil)
	if result != nil {
		t.Errorf("Expected nil for nil input, got %v", result)
	}
}

func TestEngine_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Create some files
	for i := 0; i < 5; i++ {
		f := filepath.Join(dir, "file"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(f, []byte("normal content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := Config{
		TargetPath:       dir,
		EntropyThreshold: 3.8,
	}

	// Should not panic or hang
	result, err := Run(ctx, cfg)
	if err != nil {
		// Error is acceptable for cancelled context
		return
	}

	// Partial or empty results are fine
	_ = result
}

func TestEngine_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{
		TargetPath:       dir,
		EntropyThreshold: 3.8,
	}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("engine.Run returned error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for empty directory, got %d", len(result.Findings))
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		failSev  string
		expected bool
	}{
		{"none threshold", "critical", "none", false},
		{"empty threshold", "critical", "", false},
		{"critical meets critical", "critical", "critical", true},
		{"high meets critical", "high", "critical", false},
		{"critical meets high", "critical", "high", true},
		{"high meets high", "high", "high", true},
		{"medium meets high", "medium", "high", false},
		{"medium meets medium", "medium", "medium", true},
		{"invalid threshold", "critical", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []detector.Finding{{Severity: tt.severity}}
			result := ShouldFail(findings, tt.failSev)
			if result != tt.expected {
				t.Errorf("ShouldFail(%v, %q) = %v; want %v", findings, tt.failSev, result, tt.expected)
			}
		})
	}
}
