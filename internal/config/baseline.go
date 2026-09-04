package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"leakscan/internal/detector"
)

var lineSuffixRegex = regexp.MustCompile(`:\d+.*$`)

// BaselineEntry represents a single cryptographically fingerprinted secret exception.
type BaselineEntry struct {
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Location string `json:"location"`
	Severity string `json:"severity"`
}

// Baseline represents a serialized snapshot of existing suppressed findings.
type Baseline struct {
	Version       string          `json:"version"`
	CreatedAt     string          `json:"created_at"`
	TotalFindings int             `json:"total_findings"`
	Fingerprints  []BaselineEntry `json:"fingerprints"`
	hashSet       map[string]bool
}

// ComputeFingerprint calculates an immutable SHA256 signature for a finding.
// It combines the secret type, normalized file path (independent of line shifts),
// and the redacted secret pattern so no raw secret is ever saved to disk.
func ComputeFingerprint(f detector.Finding) string {
	normPath := normalizeLocationPath(f.Location)
	payload := fmt.Sprintf("%s:%s:%s", strings.TrimSpace(f.Type), normPath, strings.TrimSpace(f.Redacted))
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// normalizeLocationPath extracts the file path without line numbers or author info.
func normalizeLocationPath(loc string) string {
	// Strip git author/date annotations, e.g. "path.go:10 (author: Jane)"
	if idx := strings.Index(loc, " ("); idx != -1 {
		loc = loc[:idx]
	}
	// Strip line numbers, e.g. "path/to/file.go:42" -> "path/to/file.go"
	cleaned := lineSuffixRegex.ReplaceAllString(loc, "")
	return filepath.ToSlash(filepath.Clean(cleaned))
}

// SaveBaseline writes a list of findings to a baseline JSON file.
func SaveBaseline(targetPath string, findings []detector.Finding) error {
	entries := make([]BaselineEntry, 0, len(findings))
	seen := make(map[string]bool)

	for _, f := range findings {
		fp := ComputeFingerprint(f)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		entries = append(entries, BaselineEntry{
			Hash:     fp,
			Type:     f.Type,
			Location: normalizeLocationPath(f.Location),
			Severity: f.Severity,
		})
	}

	b := Baseline{
		Version:       "1.0",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		TotalFindings: len(entries),
		Fingerprints:  entries,
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode baseline: %w", err)
	}

	if err := os.WriteFile(targetPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline file '%s': %w", targetPath, err)
	}

	return nil
}

// LoadBaseline loads and parses a baseline JSON file.
func LoadBaseline(sourcePath string) (*Baseline, error) {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file '%s': %w", sourcePath, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file '%s': %w", sourcePath, err)
	}

	b.hashSet = make(map[string]bool, len(b.Fingerprints))
	for _, entry := range b.Fingerprints {
		b.hashSet[entry.Hash] = true
	}

	return &b, nil
}

// IsSuppressed checks whether a finding exists in this baseline.
func (b *Baseline) IsSuppressed(f detector.Finding) bool {
	if b == nil || len(b.hashSet) == 0 {
		return false
	}
	fp := ComputeFingerprint(f)
	return b.hashSet[fp]
}

// FilterAgainstBaseline partitions findings into active (new) and suppressed (in baseline).
func FilterAgainstBaseline(findings []detector.Finding, baseline *Baseline) (active []detector.Finding, suppressed []detector.Finding) {
	if baseline == nil {
		return findings, nil
	}

	for _, f := range findings {
		if baseline.IsSuppressed(f) {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}

	return active, suppressed
}
