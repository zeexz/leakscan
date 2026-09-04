package detector

import (
	"testing"
)

func TestHasIgnoreDirective(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prevLine string
		ruleID   string
		want     bool
	}{
		{
			name:     "same-line standard ignore",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE" // leakscan:ignore`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "same-line python comment with reason",
			line:     `API_KEY = "AKIAIOSFODNN7EXAMPLE" # leakscan:ignore reason="fake fixture"`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "same-line specific matching rule",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE" // leakscan:ignore[aws-access-key-id]`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "same-line specific mismatched rule",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE" // leakscan:ignore[slack-token]`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     false,
		},
		{
			name:     "previous-line comment ignore",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE"`,
			prevLine: `// leakscan:ignore`,
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "previous-line rule-specific ignore",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE"`,
			prevLine: `// leakscan:ignore[aws-access-key-id]`,
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "previous-line not a comment should not ignore",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE"`,
			prevLine: `var str = "leakscan:ignore"`,
			ruleID:   "aws-access-key-id",
			want:     false,
		},
		{
			name:     "c-style multiline comment ignore",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE" /* leakscan:ignore */`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     true,
		},
		{
			name:     "no ignore directive present",
			line:     `apiKey := "AKIAIOSFODNN7EXAMPLE"`,
			prevLine: "",
			ruleID:   "aws-access-key-id",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasIgnoreDirective(tt.line, tt.prevLine, tt.ruleID)
			if got != tt.want {
				t.Errorf("HasIgnoreDirective() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegexDetector_InlineIgnore(t *testing.T) {
	ruleSet := &RuleSet{
		Rules: []Rule{
			{
				ID:          "aws-access-key-id",
				Name:        "AWS Access Key ID",
				Pattern:     `\b(AKIA[0-9A-Z]{16})\b`,
				Severity:    "high",
				Remediation: "Rotate AWS key",
			},
		},
	}

	det, err := NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	content := `
// This should be flagged
key1 := "AKIAIOSFODNN7EXAMPLE"

// This should be ignored by same-line directive
key2 := "AKIAIOSFODNN7EXAMPLL" // leakscan:ignore

// leakscan:ignore
key3 := "AKIAIOSFODNN7EXAMPLM"

// This should be ignored by specific rule
key4 := "AKIAIOSFODNN7EXAMPLN" // leakscan:ignore[aws-access-key-id]

// This should NOT be ignored because rule mismatch
key5 := "AKIAIOSFODNN7EXAMPLO" // leakscan:ignore[slack-token]
`

	findings := det.Detect(content, SourceMeta{Type: "file", Path: "test.go"})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (key1 and key5), got %d findings: %+v", len(findings), findings)
	}
}

func TestEntropyDetector_InlineIgnore(t *testing.T) {
	det := NewEntropyDetector(3.5)

	content := `
secret_token = "4N9xk0w2Pz8qL1mVaZbY"
secret_token2 = "4N9xk0w2Pz8qL1mVaZbY" // leakscan:ignore
`

	findings := det.Detect(content, SourceMeta{Type: "file", Path: "test.py"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (only unignored), got %d", len(findings))
	}
}
