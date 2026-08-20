package detector

import (
	"math"
	"testing"
)

func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		minScore float64
		maxScore float64
	}{
		{
			input:    "aaaaa",
			minScore: 0.0,
			maxScore: 0.0001,
		},
		{
			input:    "abcdefghijklmnopqrstuvwxyz",
			minScore: 4.6,
			maxScore: 4.8,
		},
		{
			input:    "g9A2#xK!8vP$1mL9@qW3zR7*",
			minScore: 4.2,
			maxScore: 4.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			score := CalculateShannonEntropy(tt.input)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Entropy of %q = %f; want between %f and %f", tt.input, score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestEntropyDetector_PlaceholderSuppression(t *testing.T) {
	det := NewEntropyDetector(3.8)

	placeholders := []string{
		"SECRET_KEY=your-key-here",
		"API_TOKEN=CHANGEME",
		"PASSWORD=<REDACTED>",
		"AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxx",
	}

	for _, line := range placeholders {
		meta := SourceMeta{Type: "file", Path: "config.env", LineNumber: 1}
		findings := det.Detect(line, meta)
		if len(findings) > 0 {
			t.Errorf("Expected placeholder line %q to be suppressed, but got %d findings", line, len(findings))
		}
	}
}

func TestEntropyDetector_HighEntropySecretDetection(t *testing.T) {
	det := NewEntropyDetector(3.8)

	highEntropyLine := "CUSTOM_API_TOKEN=g9A2xK8vP1mL9qW3zR7kPqXw"
	meta := SourceMeta{Type: "file", Path: ".env", LineNumber: 5}

	findings := det.Detect(highEntropyLine, meta)
	if len(findings) == 0 {
		t.Fatalf("Expected high entropy secret to be detected, got 0 findings")
	}

	if findings[0].Severity != "high" {
		t.Errorf("Expected severity 'high', got %q", findings[0].Severity)
	}

	// Verify redaction was applied
	if math.Abs(float64(len(findings[0].Redacted)-len(highEntropyLine))) > 20 && findings[0].Redacted == highEntropyLine {
		t.Errorf("Redacted secret value should not be equal to raw line")
	}
}
