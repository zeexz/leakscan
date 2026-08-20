package detector

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// Tightened regex: requires alphanumeric-heavy values with limited special chars.
	// Excludes version strings, URLs, and module paths by disallowing consecutive dots/slashes.
	envAssignRegex = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_\-\.]*)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\+/=]{12,})['"]?`)
	placeholderSet = map[string]bool{
		"your-key-here":          true,
		"your_key_here":          true,
		"changeme":               true,
		"<redacted>":             true,
		"redacted":               true,
		"xxx":                    true,
		"xxxx":                   true,
		"xxxxxxxx":               true,
		"12345678":               true,
		"1234567890":             true,
		"dummy":                  true,
		"placeholder":            true,
		"example":                true,
		"0000000000000000":       true,
		"aaaaaaaaaaaaaaaa":       true,
		"abcdefghijklmnopqrstuv": true,
	}
)

// EntropyDetector flags high-randomness secret-like strings.
type EntropyDetector struct {
	Threshold float64
}

// NewEntropyDetector creates a new EntropyDetector with specified entropy threshold.
func NewEntropyDetector(threshold float64) *EntropyDetector {
	if threshold <= 0 {
		threshold = 3.8
	}
	return &EntropyDetector{Threshold: threshold}
}

func (e *EntropyDetector) Detect(content string, source SourceMeta) []Finding {
	var findings []Finding

	// Skip candidate sample/example files
	if isSampleFile(source.Path) {
		return findings
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lineNum := source.LineNumber
		if lineNum <= 0 {
			lineNum = i + 1
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		matches := envAssignRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 3 {
				continue
			}
			varName := strings.ToLower(m[1])
			val := m[2]

			// Skip placeholders
			if isPlaceholder(val) {
				continue
			}

			// Check if var name or string length indicates candidate secret
			isSecretVarName := strings.Contains(varName, "key") ||
				strings.Contains(varName, "secret") ||
				strings.Contains(varName, "token") ||
				strings.Contains(varName, "pass") ||
				strings.Contains(varName, "auth") ||
				strings.Contains(varName, "cred")

			entropy := CalculateShannonEntropy(val)

			if (isSecretVarName && entropy >= e.Threshold) || (len(val) >= 20 && entropy >= e.Threshold+0.4) {
				srcStr, locStr := formatSourceAndLocation(source, lineNum)
				findings = append(findings, Finding{
					Source:      srcStr,
					Type:        "High Entropy String / Potential Secret",
					Location:    locStr,
					Severity:    "high",
					Redacted:    RedactValue(val),
					Remediation: "High entropy string assigned to secret variable. Verify if this is an API key/token and move to secure secret store.",
				})
			}
		}
	}

	return findings
}

// CalculateShannonEntropy calculates Shannon entropy H(X) = -sum(p * log2(p))
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isPlaceholder(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	if placeholderSet[lower] {
		return true
	}
	for ph := range placeholderSet {
		if strings.Contains(lower, ph) {
			return true
		}
	}
	return false
}

func isSampleFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(base, ".example") ||
		strings.HasSuffix(base, ".sample") ||
		strings.HasSuffix(base, ".template") ||
		strings.Contains(base, "example")
}
