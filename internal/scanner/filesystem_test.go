package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"leakscan/internal/config"
	"leakscan/internal/detector"
	"leakscan/rules"
)

// testDetectors creates a standard set of detectors for testing.
func testDetectors(t *testing.T) []detector.Detector {
	t.Helper()
	ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	regexDet, err := detector.NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}
	return []detector.Detector{regexDet, detector.NewEntropyDetector(3.8)}
}

func TestFilesystemScanner_DetectsSecretInFile(t *testing.T) {
	dir := t.TempDir()

	// Plant a fake secret
	envFile := filepath.Join(dir, ".env")
	content := "AWS_ACCESS_KEY_ID=" + "AKIA" + "TESTKEY1234567890"
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected at least 1 finding for planted AWS key, got 0")
	}

	// Verify the finding is properly redacted
	for _, f := range findings {
		if f.Redacted == content {
			t.Errorf("Finding.Redacted contains raw secret")
		}
	}
}

func TestFilesystemScanner_IgnoresPatterns(t *testing.T) {
	dir := t.TempDir()

	// Create an ignored directory structure
	nodeModules := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nodeModules, 0755); err != nil {
		t.Fatal(err)
	}

	// Plant a secret inside node_modules (should be ignored by default)
	secretFile := filepath.Join(nodeModules, "config.env")
	content := "SECRET_KEY=" + "ghp_" + "ABCDEFghijklmnop1234567890abcdefghij"
	if err := os.WriteFile(secretFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// node_modules should be ignored by default patterns
	for _, f := range findings {
		if filepath.Base(f.Location) == "config.env" {
			t.Errorf("Expected node_modules/config.env to be ignored, but got finding: %+v", f)
		}
	}
}

func TestFilesystemScanner_SkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a file with null bytes (binary)
	binFile := filepath.Join(dir, "data.bin")
	data := []byte("SECRET_KEY=abc123def456\x00\x00\x00binary content")
	if err := os.WriteFile(binFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	for _, f := range findings {
		if f.Location == "data.bin:1" || f.Source == "file:data.bin" {
			t.Errorf("Expected binary file to be skipped, but got finding: %+v", f)
		}
	}
}

func TestFilesystemScanner_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Create some files
	for i := 0; i < 10; i++ {
		f := filepath.Join(dir, "file"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(f, []byte("normal content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.Scan(ctx)
	// Should return without error (context errors are handled gracefully)
	if err != nil && err != context.Canceled {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestFilesystemScanner_MaxFileSize(t *testing.T) {
	dir := t.TempDir()

	// Create a file that exceeds max size
	largeFile := filepath.Join(dir, "large.env")
	content := "SECRET_KEY=" + "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890\n"
	// Repeat to make it larger than 100 bytes
	largeContent := ""
	for i := 0; i < 10; i++ {
		largeContent += content
	}
	if err := os.WriteFile(largeFile, []byte(largeContent), 0644); err != nil {
		t.Fatal(err)
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)
	scanner.SetMaxFileSize(100) // Set very low max to trigger skip

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// File should be skipped due to size limit
	if len(findings) > 0 {
		t.Errorf("Expected 0 findings (file should be skipped due to size limit), got %d", len(findings))
	}
}

func TestFilesystemScanner_WorldReadablePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File permission checks are not applicable on Windows")
	}

	dir := t.TempDir()

	// Create a .env file with world-readable permissions
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("SAFE=true"), 0644); err != nil {
		t.Fatal(err)
	}

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Should detect the file permission issue
	hasPermFinding := false
	for _, f := range findings {
		if f.Type == "Insecure World-Readable File Permission" {
			hasPermFinding = true
			break
		}
	}

	if !hasPermFinding {
		t.Error("Expected file permission finding for world-readable .env file")
	}
}

func TestFilesystemScanner_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	detectors := testDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewFilesystemScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty directory, got %d", len(findings))
	}
}

func TestFilesystemScanner_Name(t *testing.T) {
	scanner := NewFilesystemScanner(".", nil, nil)
	if scanner.Name() != "filesystem" {
		t.Errorf("Expected name 'filesystem', got %q", scanner.Name())
	}
}
