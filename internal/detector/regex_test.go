package detector

import (
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
