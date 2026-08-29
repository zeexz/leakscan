package scanner

import (
	"context"
	"testing"

	"leakscan/internal/detector"
	"leakscan/rules"
)

func processTestDetectors(t *testing.T) []detector.Detector {
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

func TestProcessScanner_GenericFallback(t *testing.T) {
	detectors := processTestDetectors(t)
	scanner := NewProcessScanner(detectors)

	// Should not panic regardless of OS
	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan should not return error: %v", err)
	}

	// We can't assert specific findings since it depends on the current
	// process environment, but we verify no panic and proper structure
	for _, f := range findings {
		if f.Source == "" {
			t.Errorf("Finding should have a non-empty source")
		}
		if f.Redacted == "" {
			t.Errorf("Finding should have a non-empty redacted value")
		}
	}
}

func TestProcessScanner_ContextCancellation(t *testing.T) {
	detectors := processTestDetectors(t)
	scanner := NewProcessScanner(detectors)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should return gracefully
	_, err := scanner.Scan(ctx)
	if err != nil && err != context.Canceled {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestProcessScanner_Name(t *testing.T) {
	scanner := NewProcessScanner(nil)
	if scanner.Name() != "process_env" {
		t.Errorf("Expected name 'process_env', got %q", scanner.Name())
	}
}
