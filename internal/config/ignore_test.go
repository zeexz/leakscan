package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreMatcher_DefaultPatterns(t *testing.T) {
	matcher := NewIgnoreMatcher("")

	// Default patterns should ignore common noise directories
	defaults := []struct {
		path     string
		expected bool
	}{
		{".git", true},
		{"node_modules", true},
		{"vendor", true},
		{"image.png", true},
		{"photo.jpg", true},
		{"binary.exe", true},
		{"archive.zip", true},
		{"font.woff2", true},
		{"go.sum", true},
		{"package-lock.json", true},
		{"main.go", false},
		{".env", false},
		{"config.yaml", false},
		{"README.md", false},
	}

	for _, tt := range defaults {
		result := matcher.ShouldIgnore(tt.path)
		if result != tt.expected {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestIgnoreMatcher_CustomFile(t *testing.T) {
	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, ".leakscanner-ignore")

	content := `# Custom ignore patterns
test_data/
*.fixture
mock_secrets.env
`
	if err := os.WriteFile(ignoreFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	matcher := NewIgnoreMatcher(ignoreFile)

	tests := []struct {
		path     string
		expected bool
	}{
		{"test_data/secrets.env", true},
		{"file.fixture", true},
		{"mock_secrets.env", true},
		{"real_secrets.env", false},
		{"src/main.go", false},
	}

	for _, tt := range tests {
		result := matcher.ShouldIgnore(tt.path)
		if result != tt.expected {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestIgnoreMatcher_GlobMatching(t *testing.T) {
	matcher := NewIgnoreMatcher("")

	tests := []struct {
		path     string
		expected bool
	}{
		// Test file glob patterns
		{"test_main_test.go", true},  // *_test.go
		{"main_test.py", true},       // *_test.py
		{"app.test.js", true},        // *.test.js
		{"component.spec.ts", true},  // *.spec.ts
		// Non-matching
		{"main.go", false},
		{"test_helper.go", false},
	}

	for _, tt := range tests {
		result := matcher.ShouldIgnore(tt.path)
		if result != tt.expected {
			t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestIgnoreMatcher_EmptyAndCommentLines(t *testing.T) {
	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, "ignore")

	content := `
# This is a comment
   # Indented comment

*.secret

   
# Another comment
`
	if err := os.WriteFile(ignoreFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	matcher := NewIgnoreMatcher(ignoreFile)

	// *.secret should be loaded despite comments and blank lines
	if !matcher.ShouldIgnore("test.secret") {
		t.Error("Expected *.secret pattern to match test.secret")
	}

	// Comments should not be loaded as patterns
	if matcher.ShouldIgnore("# This is a comment") {
		t.Error("Comments should not be treated as ignore patterns")
	}
}

func TestIgnoreMatcher_NonexistentFile(t *testing.T) {
	// Should still work with default patterns when file doesn't exist
	matcher := NewIgnoreMatcher("/nonexistent/path/.leakscanner-ignore")

	// Default patterns should still work
	if !matcher.ShouldIgnore("node_modules") {
		t.Error("Default patterns should still apply when ignore file doesn't exist")
	}
}

func TestDefaultIgnorePatterns(t *testing.T) {
	patterns := DefaultIgnorePatterns()
	if len(patterns) == 0 {
		t.Fatal("DefaultIgnorePatterns should return non-empty list")
	}

	// Verify critical patterns are present
	hasGit := false
	hasNodeModules := false
	for _, p := range patterns {
		if p == ".git" {
			hasGit = true
		}
		if p == "node_modules" {
			hasNodeModules = true
		}
	}

	if !hasGit {
		t.Error("DefaultIgnorePatterns should include .git")
	}
	if !hasNodeModules {
		t.Error("DefaultIgnorePatterns should include node_modules")
	}
}
