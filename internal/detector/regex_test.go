package detector

import (
	"strings"
	"testing"

	"leakscan/rules"
)

func TestRegexDetector_TruePositives(t *testing.T) {
	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	det, err := NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}

	tests := []struct {
		name         string
		content      string
		expectedType string
	}{
		{
			name:         "AWS Access Key ID",
			content:      "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
			expectedType: "AWS Access Key ID",
		},
		{
			name:         "GitHub PAT Token",
			content:      "export GITHUB_TOKEN=" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
			expectedType: "GitHub Personal Access Token",
		},
		{
			name:         "Slack API Token",
			content:      "slack_token: " + "xoxb" + "-1234567890-abcdef1234567890",
			expectedType: "Slack API Token",
		},
		{
			name:         "RSA Private Key Header",
			content:      "-----BEGIN RSA PRIVATE KEY-----",
			expectedType: "Private Key Header",
		},
		{
			name:         "Generic Environment Secret Assignment",
			content:      "DB_PASSWORD=SuperSecretPassWord123!",
			expectedType: "Generic Environment Secret Assignment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := SourceMeta{Type: "file", Path: ".env", LineNumber: 1}
			findings := det.Detect(tt.content, meta)

			if len(findings) == 0 {
				t.Fatalf("Expected detection for %s, got 0 findings", tt.name)
			}

			found := false
			for _, f := range findings {
				if f.Type == tt.expectedType {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected finding type %q, got findings: %+v", tt.expectedType, findings)
			}
		})
	}
}

func TestRegexDetector_FalsePositives(t *testing.T) {
	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	det, err := NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Normal comment line",
			content: "# This is a regular code comment with no secrets",
		},
		{
			name:    "Regular variable assignment",
			content: "MAX_RETRIES=5",
		},
		{
			name:    "HTML tag",
			content: "<div class='container'>Hello World</div>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := SourceMeta{Type: "file", Path: "main.go", LineNumber: 10}
			findings := det.Detect(tt.content, meta)

			if len(findings) > 0 {
				t.Errorf("Expected 0 findings for non-secret line, got %d findings: %+v", len(findings), findings)
			}
		})
	}
}

// ── Fuzz Tests ──────────────────────────────────────────────────────────────
//
// Fuzz tests feed pseudo-random mutations of an initial seed corpus into the
// target function and assert that it never panics. They are NOT run during
// 'go test ./...' — only via 'go test -fuzz=<FuzzFuncName>'.
//
// Run with:  make test-fuzz
// or:        go test -fuzz=FuzzRegexDetector_NoPanic -fuzztime=60s ./internal/detector/

// FuzzRegexDetector_NoPanic verifies that Detect() is safe against any input
// string — it must never panic regardless of what the fuzzer generates.
func FuzzRegexDetector_NoPanic(f *testing.F) {
	// Seed the fuzzer with interesting starting values.
	// The fuzzer will mutate these to explore edge cases.
	f.Add("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	f.Add("export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz")
	f.Add("-----BEGIN RSA PRIVATE KEY-----")
	f.Add("")
	f.Add("\x00\x01\x02\xff")                // Raw bytes
	f.Add("normal_var=123")                  // Benign assignment
	f.Add(strings.Repeat("A", 10_000))       // Very long line
	f.Add("key=" + strings.Repeat("x", 200)) // Long value

	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		f.Fatalf("Failed to load rules: %v", err)
	}
	det, err := NewRegexDetector(ruleSet)
	if err != nil {
		f.Fatalf("Failed to create regex detector: %v", err)
	}

	f.Fuzz(func(t *testing.T, content string) {
		// Must not panic — findings may be anything
		meta := SourceMeta{Type: "file", Path: "fuzz.txt", LineNumber: 0}
		_ = det.Detect(content, meta)
	})
}

// FuzzLoadRulesFromYAML_NoPanic verifies the YAML parser is safe against
// arbitrary byte sequences — it must return an error or a RuleSet, never panic.
func FuzzLoadRulesFromYAML_NoPanic(f *testing.F) {
	// Seed with valid YAML and intentionally malformed inputs
	f.Add([]byte("rules:\n  - id: test\n    pattern: 'abc'\n"))
	f.Add([]byte("{invalid yaml"))
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(strings.Repeat("- ", 1000)))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Either returns a result or an error — never panics
		_, _ = LoadRulesFromYAML(data)
	})
}
