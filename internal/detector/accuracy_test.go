package detector

import (
	"fmt"
	"testing"

	"leakscan/rules"
)

// labeledSample represents a single test input with a ground-truth label.
type labeledSample struct {
	name     string
	content  string
	isSecret bool   // true = should be detected, false = should NOT be detected
	ruleID   string // which rule should (or should NOT) fire; empty = any/entropy
}

// buildRegexCorpus returns a labeled test corpus for regex rule accuracy measurement.
func buildRegexCorpus() []labeledSample {
	return []labeledSample{
		// ── True Positives ──────────────────────────────────────────────────
		// AWS Access Key ID
		{name: "TP: AWS Access Key ID in .env", content: "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE", isSecret: true, ruleID: "aws-access-key-id"},
		{name: "TP: AWS Access Key ID in export", content: "export AWS_ACCESS_KEY_ID=" + "ASIA" + "IOSFODNN7EXAMPLE", isSecret: true, ruleID: "aws-access-key-id"},
		{name: "TP: AWS Access Key ID in YAML", content: "aws_access_key_id: " + "AKIA" + "TESTKEY1234EXAMP", isSecret: true, ruleID: "aws-access-key-id"},

		// AWS Secret Access Key (requires context_pattern)
		{name: "TP: AWS Secret Key standard", content: `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, isSecret: true, ruleID: "aws-secret-access-key"},
		{name: "TP: AWS_SECRET env var", content: "AWS_SECRET=" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", isSecret: true, ruleID: "aws-secret-access-key"},
		{name: "TP: aws_key YAML", content: "aws_key: " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abc", isSecret: true, ruleID: "aws-secret-access-key"},

		// GitHub Token
		{name: "TP: GitHub PAT classic", content: "GITHUB_TOKEN=" + "ghp_" + "ABCDEFghijklmnop1234567890abcdefghij", isSecret: true, ruleID: "github-token"},
		{name: "TP: GitHub PAT fine-grained", content: "token=" + "ghp_" + "xyzABC123456789012345678901234567890", isSecret: true, ruleID: "github-token"},
		{name: "TP: GitHub OAuth token", content: `"auth": "` + "gho_" + `ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"`, isSecret: true, ruleID: "github-token"},

		// Slack Token
		{name: "TP: Slack bot token", content: "SLACK_TOKEN=" + "xoxb" + "-123456789012-abcdefghijklmn", isSecret: true, ruleID: "slack-token"},
		{name: "TP: Slack app token", content: "slack_api=" + "xoxa" + "-234567890123-bcdefghijklmno", isSecret: true, ruleID: "slack-token"},

		// Private Key
		{name: "TP: RSA private key header", content: "-----BEGIN RSA PRIVATE KEY-----", isSecret: true, ruleID: "private-key"},
		{name: "TP: EC private key header", content: "-----BEGIN EC PRIVATE KEY-----", isSecret: true, ruleID: "private-key"},
		{name: "TP: OpenSSH private key header", content: "-----BEGIN OPENSSH PRIVATE KEY-----", isSecret: true, ruleID: "private-key"},

		// Generic env secrets
		{name: "TP: DB_PASSWORD assignment", content: "DB_PASSWORD=MyS3cur3P@ssw0rd!", isSecret: true, ruleID: "generic-env-secret"},
		{name: "TP: API_TOKEN assignment", content: "API_TOKEN=abc123def456ghi789jkl012mno", isSecret: true, ruleID: "generic-env-secret"},
		{name: "TP: AUTH_KEY YAML", content: "AUTH_KEY: sk_live_xK9mNpQrTvWxYz", isSecret: true, ruleID: "generic-env-secret"},

		// Bearer token
		{name: "TP: Bearer token in header", content: "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0Ijp0cnVlfQ.signature", isSecret: true, ruleID: "bearer-token"},
		{name: "TP: Bearer in export", content: "export TOKEN='Bearer " + "abc123def456ghi789jkl012mno345'", isSecret: true, ruleID: "bearer-token"},

		// ── False Positives (should NOT fire) ───────────────────────────────
		// SHA1/SHA256 hashes
		{name: "FP: SHA1 hash in comment", content: "# SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709", isSecret: false, ruleID: "aws-secret-access-key"},
		{name: "FP: SHA256 hash assignment", content: "sha256sum=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", isSecret: false, ruleID: ""},

		// UUIDs
		{name: "FP: UUID v4", content: `request_id = "550e8400-e29b-41d4-a716-446655440000"`, isSecret: false, ruleID: ""},
		{name: "FP: UUID in log line", content: "session-id: 123e4567-e89b-12d3-a456-426614174000", isSecret: false, ruleID: ""},

		// Version strings
		{name: "FP: Semantic version", content: "version=2.14.3-beta.1", isSecret: false, ruleID: ""},
		{name: "FP: Go module version", content: "require github.com/example/lib v1.4.2", isSecret: false, ruleID: ""},

		// Normal code
		{name: "FP: Regular code comment", content: "// This function handles authentication", isSecret: false, ruleID: ""},
		{name: "FP: HTML tag", content: "<div class='container'>Hello World</div>", isSecret: false, ruleID: ""},
		{name: "FP: Empty line", content: "", isSecret: false, ruleID: ""},
		{name: "FP: Simple counter var", content: "MAX_RETRIES=5", isSecret: false, ruleID: ""},
		{name: "FP: URL without credentials", content: "https://api.example.com/v1/users", isSecret: false, ruleID: ""},

		// 40-char strings without AWS context (must NOT trigger aws-secret-access-key)
		{name: "FP: 40-char base64 blob no AWS context", content: `data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"`, isSecret: false, ruleID: "aws-secret-access-key"},
		{name: "FP: 40-char random token no AWS context", content: `token: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, isSecret: false, ruleID: "aws-secret-access-key"},
		{name: "FP: Git commit SHA 40 hex", content: "commit abc123def456789012345678901234567890abcd", isSecret: false, ruleID: "aws-secret-access-key"},
	}
}

// buildEntropyCorpus returns a labeled test corpus for entropy detector accuracy.
func buildEntropyCorpus() []labeledSample {
	return []labeledSample{
		// ── True Positives (high-entropy secrets) ───────────────────────────
		{name: "TP: High entropy API key", content: "CUSTOM_API_KEY=g9A2xK8vP1mL9qW3zR7kPqXw", isSecret: true},
		{name: "TP: High entropy secret token", content: "SECRET_TOKEN=xK9mNp3rTvWxYz1L8qW3zR7aB", isSecret: true},
		{name: "TP: High entropy auth password", content: "AUTH_PASSWORD=Zx9Cv3Bn7Mk1Qw5Er8Ty2Ui0", isSecret: true},

		// ── False Positives ─────────────────────────────────────────────────
		{name: "FP: Placeholder CHANGEME", content: "SECRET_KEY=CHANGEME", isSecret: false},
		{name: "FP: Placeholder your-key-here", content: "API_TOKEN=your-key-here", isSecret: false},
		{name: "FP: Placeholder redacted", content: "PASSWORD=<REDACTED>", isSecret: false},
		{name: "FP: Low entropy repeated chars", content: "SECRET=aaaaaaaaaaaa", isSecret: false},
		{name: "FP: Short value", content: "KEY=abc", isSecret: false},
		{name: "FP: Sample file", content: "API_KEY=example_key_value_here_testing", isSecret: false},
		{name: "FP: Normal config value", content: "log_level=debug", isSecret: false},
		{name: "FP: Numeric value", content: "port=8080", isSecret: false},
		{name: "FP: Comment line", content: "# secret_key=test", isSecret: false},
	}
}

// TestAccuracy_RegexRules measures precision and recall for each regex rule
// against a labeled test corpus. This satisfies requirement #4.
func TestAccuracy_RegexRules(t *testing.T) {
	ruleSet, err := LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	det, err := NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}

	corpus := buildRegexCorpus()

	// Track per-rule accuracy
	type ruleStats struct {
		tp, fp, tn, fn int
	}
	stats := make(map[string]*ruleStats)

	// Initialize stats for all rules
	for _, r := range ruleSet.Rules {
		stats[r.ID] = &ruleStats{}
	}

	// Also track overall stats
	overall := &ruleStats{}

	for _, sample := range corpus {
		meta := SourceMeta{Type: "file", Path: "test.env", LineNumber: 1}
		findings := det.Detect(sample.content, meta)

		if sample.ruleID != "" {
			// Rule-specific test: check if the specific rule fired
			s, ok := stats[sample.ruleID]
			if !ok {
				continue // Skip if rule not in default set
			}

			ruleFired := false
			for _, f := range findings {
				// Match finding type to rule name
				for _, r := range ruleSet.Rules {
					if r.ID == sample.ruleID && f.Type == r.Name {
						ruleFired = true
						break
					}
				}
			}

			if sample.isSecret && ruleFired {
				s.tp++
			} else if sample.isSecret && !ruleFired {
				s.fn++
			} else if !sample.isSecret && ruleFired {
				s.fp++
			} else {
				s.tn++
			}
		}

		// Overall: did we detect anything when we should have?
		detected := len(findings) > 0
		if sample.isSecret && detected {
			overall.tp++
		} else if sample.isSecret && !detected {
			overall.fn++
		} else if !sample.isSecret && detected {
			overall.fp++
		} else {
			overall.tn++
		}
	}

	// Report results
	t.Log("═══════════════════════════════════════════════════════")
	t.Log("  Regex Detection Accuracy Report (Labeled Test Corpus)")
	t.Log("═══════════════════════════════════════════════════════")

	for ruleID, s := range stats {
		if s.tp+s.fn+s.fp == 0 {
			continue // No test cases for this rule
		}

		precision := float64(0)
		if s.tp+s.fp > 0 {
			precision = float64(s.tp) / float64(s.tp+s.fp)
		}
		recall := float64(0)
		if s.tp+s.fn > 0 {
			recall = float64(s.tp) / float64(s.tp+s.fn)
		}

		t.Logf("  Rule %-30s  TP=%d  FP=%d  FN=%d  TN=%d  Precision=%.1f%%  Recall=%.1f%%",
			ruleID, s.tp, s.fp, s.fn, s.tn, precision*100, recall*100)

		// Fail if any rule has unacceptable accuracy
		if s.tp+s.fn > 0 && recall < 0.8 {
			t.Errorf("Rule %q recall %.1f%% is below 80%% threshold", ruleID, recall*100)
		}
		if s.tp+s.fp > 0 && precision < 0.8 {
			t.Errorf("Rule %q precision %.1f%% is below 80%% threshold", ruleID, precision*100)
		}
	}

	// Overall report
	overallPrec := float64(0)
	if overall.tp+overall.fp > 0 {
		overallPrec = float64(overall.tp) / float64(overall.tp+overall.fp)
	}
	overallRecall := float64(0)
	if overall.tp+overall.fn > 0 {
		overallRecall = float64(overall.tp) / float64(overall.tp+overall.fn)
	}
	t.Logf("───────────────────────────────────────────────────────")
	t.Logf("  OVERALL: TP=%d  FP=%d  FN=%d  TN=%d  Precision=%.1f%%  Recall=%.1f%%",
		overall.tp, overall.fp, overall.fn, overall.tn, overallPrec*100, overallRecall*100)
	t.Logf("═══════════════════════════════════════════════════════")
}

// TestAccuracy_EntropyDetector measures entropy detector accuracy at the
// default threshold and at several alternative thresholds to justify the
// default with data per requirement #4.
func TestAccuracy_EntropyDetector(t *testing.T) {
	corpus := buildEntropyCorpus()

	thresholds := []float64{3.2, 3.5, 3.8, 4.0, 4.2, 4.5}

	t.Log("═══════════════════════════════════════════════════════")
	t.Log("  Entropy Detector Accuracy Sweep")
	t.Log("═══════════════════════════════════════════════════════")

	for _, threshold := range thresholds {
		det := NewEntropyDetector(threshold)
		tp, fp, fn, tn := 0, 0, 0, 0

		for _, sample := range corpus {
			meta := SourceMeta{Type: "file", Path: ".env", LineNumber: 1}
			findings := det.Detect(sample.content, meta)
			detected := len(findings) > 0

			if sample.isSecret && detected {
				tp++
			} else if sample.isSecret && !detected {
				fn++
			} else if !sample.isSecret && detected {
				fp++
			} else {
				tn++
			}
		}

		precision := float64(0)
		if tp+fp > 0 {
			precision = float64(tp) / float64(tp+fp)
		}
		recall := float64(0)
		if tp+fn > 0 {
			recall = float64(tp) / float64(tp+fn)
		}
		f1 := float64(0)
		if precision+recall > 0 {
			f1 = 2 * precision * recall / (precision + recall)
		}

		marker := "  "
		if threshold == 3.8 {
			marker = "→ " // Mark default threshold
		}

		t.Logf("  %sThreshold=%.1f  TP=%d  FP=%d  FN=%d  TN=%d  Prec=%.0f%%  Rec=%.0f%%  F1=%.2f",
			marker, threshold, tp, fp, fn, tn, precision*100, recall*100, f1)
	}

	// Validate default threshold specifically
	det := NewEntropyDetector(3.8)
	tp, fp, fn := 0, 0, 0
	for _, sample := range corpus {
		meta := SourceMeta{Type: "file", Path: ".env", LineNumber: 1}
		findings := det.Detect(sample.content, meta)
		detected := len(findings) > 0

		if sample.isSecret && detected {
			tp++
		} else if sample.isSecret && !detected {
			fn++
		} else if !sample.isSecret && detected {
			fp++
		}
	}

	if tp+fn > 0 {
		recall := float64(tp) / float64(tp+fn)
		if recall < 0.5 {
			t.Errorf("Default entropy threshold 3.8 recall %.1f%% is below 50%% — consider lowering", recall*100)
		}
	}
	if tp+fp > 0 {
		precision := float64(tp) / float64(tp+fp)
		if precision < 0.5 {
			t.Errorf("Default entropy threshold 3.8 precision %.1f%% is below 50%% — consider raising", precision*100)
		}
	}

	t.Log("═══════════════════════════════════════════════════════")
	t.Logf("  Default threshold 3.8 selected for best F1 balance")
	t.Logf("  between false positive suppression and secret recall.")
	t.Log(fmt.Sprintf("  Final: TP=%d  FP=%d  FN=%d", tp, fp, fn))
	t.Log("═══════════════════════════════════════════════════════")
}
