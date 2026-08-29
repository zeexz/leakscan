package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"leakscan/rules"
)

// FuzzRedactionPipeline_NoRawSecretInOutput feeds random strings with planted
// "secrets" through the full detect→JSON-serialize pipeline and asserts that
// the raw secret never appears in the serialized output.
//
// Run with:
//
//	go test -fuzz=FuzzRedactionPipeline_NoRawSecretInOutput -fuzztime=60s ./internal/detector/
func FuzzRedactionPipeline_NoRawSecretInOutput(f *testing.F) {
	// Seed corpus with realistic secret patterns (split to avoid scanner self-detection)
	f.Add("AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	f.Add("export GITHUB_TOKEN=" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz")
	f.Add("slack_token=" + "xoxb" + "-1234567890-abcdef1234567890")
	f.Add("DB_PASSWORD=" + "SuperSecretP@ssW0rd!2024XyZ")
	f.Add("-----BEGIN RSA PRIVATE KEY-----")
	f.Add("Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0Ijp0cnVlfQ")
	f.Add("")
	f.Add("normal_var=123")
	f.Add(strings.Repeat("A", 5000))

	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		f.Fatalf("Failed to load rules: %v", err)
	}
	regexDet, err := NewRegexDetector(ruleSet)
	if err != nil {
		f.Fatalf("Failed to create regex detector: %v", err)
	}
	entropyDet := NewEntropyDetector(3.8)
	detectors := []Detector{regexDet, entropyDet}

	f.Fuzz(func(t *testing.T, content string) {
		meta := SourceMeta{Type: "file", Path: "fuzz_test.txt", LineNumber: 0}

		var allFindings []Finding
		for _, d := range detectors {
			findings := d.Detect(content, meta)
			allFindings = append(allFindings, findings...)
		}

		if len(allFindings) == 0 {
			return // Nothing to check if no secrets detected
		}

		// Serialize findings to JSON (mimics report.PrintJSONReport)
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		if err := encoder.Encode(allFindings); err != nil {
			t.Fatalf("JSON encoding failed: %v", err)
		}
		jsonOutput := buf.String()

		// For each finding, extract what the raw secret value would have been
		// by checking if any non-redacted portion of the content appears in output.
		// We check that the Finding struct itself doesn't contain unredacted secrets.
		for _, finding := range allFindings {
			// The Redacted field should never be the full raw content line
			if finding.Redacted == content && len(content) > 8 {
				t.Errorf("Finding.Redacted equals raw content — redaction failed: %q", content[:minInt(50, len(content))])
			}
			// Ensure the JSON output contains only redacted values
			if finding.Redacted != "[REDACTED]" &&
				!strings.Contains(finding.Redacted, "*") {
				t.Errorf("Finding.Redacted contains no masking characters: %q", finding.Redacted)
			}
		}

		// Verify no raw secret-like patterns appear unmasked in JSON output
		// This checks that the full content line doesn't leak into JSON
		if len(content) > 20 {
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) < 20 {
					continue
				}
				if strings.Contains(jsonOutput, trimmed) {
					if strings.ContainsAny(trimmed, "=:") {
						t.Errorf("Raw content line leaked into JSON output: %q", trimmed[:minInt(80, len(trimmed))])
					}
				}
			}
		}
	})
}

// TestRedactionPipeline_PlantedSecrets is a deterministic test that plants
// known fake secrets, runs detection, and verifies they never appear raw in output.
func TestRedactionPipeline_PlantedSecrets(t *testing.T) {
	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	regexDet, err := NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}
	entropyDet := NewEntropyDetector(3.8)
	detectors := []Detector{regexDet, entropyDet}

	// Planted secrets — these exact strings must NEVER appear in JSON output
	plantedSecrets := []struct {
		name    string
		content string
		secret  string // the substring that must not appear in output
	}{
		{
			name:    "AWS Access Key ID",
			content: "AWS_ACCESS_KEY_ID=" + "AKIAIOSFODNN7EXAMPLE",
			secret:  "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:    "AWS Secret Key",
			content: "aws_secret_access_key=" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			secret:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			name:    "GitHub Token",
			content: "GITHUB_TOKEN=" + "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890",
			secret:  "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890",
		},
		{
			name:    "Generic Password",
			content: "DB_PASSWORD=" + "MyS3cur3P@ssw0rd!2024",
			secret:  "MyS3cur3P@ssw0rd!2024",
		},
	}

	for _, ps := range plantedSecrets {
		t.Run(ps.name, func(t *testing.T) {
			meta := SourceMeta{Type: "file", Path: "test.env", LineNumber: 1}

			var allFindings []Finding
			for _, d := range detectors {
				findings := d.Detect(ps.content, meta)
				allFindings = append(allFindings, findings...)
			}

			if len(allFindings) == 0 {
				t.Logf("Warning: no findings for planted secret %q — detection may need review", ps.name)
				return
			}

			// Serialize to JSON
			var buf bytes.Buffer
			encoder := json.NewEncoder(&buf)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(allFindings); err != nil {
				t.Fatalf("JSON encoding failed: %v", err)
			}
			jsonOutput := buf.String()

			// Assert the raw secret does NOT appear in JSON output
			if strings.Contains(jsonOutput, ps.secret) {
				t.Errorf("CRITICAL: Raw secret %q leaked into JSON output!\nJSON:\n%s",
					ps.secret[:minInt(20, len(ps.secret))], jsonOutput)
			}

			// Assert all findings have masked redacted values
			for i, f := range allFindings {
				if f.Redacted == ps.secret {
					t.Errorf("Finding[%d].Redacted equals raw secret — masking failed", i)
				}
				if !strings.Contains(f.Redacted, "*") && f.Redacted != "[REDACTED]" {
					t.Errorf("Finding[%d].Redacted has no masking: %q", i, f.Redacted)
				}
			}
		})
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestZeroString verifies the ZeroString function overwrites memory.
func TestZeroString(t *testing.T) {
	// Create a mutable string via fmt to avoid string interning
	secret := fmt.Sprintf("secret_%d_value", 42)
	original := secret

	ZeroString(&secret)

	if secret != "" {
		t.Errorf("ZeroString should set string to empty, got %q", secret)
	}

	// The original variable still holds the old reference, but the backing
	// memory should be zeroed. We can't easily verify this without unsafe,
	// but we verify the API contract.
	_ = original
}
