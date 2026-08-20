package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreMatcher holds pattern rules to exclude files and directories from scanning.
type IgnoreMatcher struct {
	patterns []string
}

// DefaultIgnorePatterns returns built-in common noise/binary patterns to ignore.
func DefaultIgnorePatterns() []string {
	return []string{
		// Version control
		".git",
		".git/*",

		// Dependency directories
		"node_modules",
		"node_modules/*",
		"vendor",
		"vendor/*",

		// Lockfiles (contain checksums/hashes, not secrets)
		"go.sum",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"Cargo.lock",
		"composer.lock",
		"Gemfile.lock",
		"poetry.lock",
		"Pipfile.lock",

		// IDE / Editor
		".idea",
		".vscode",

		// Images
		"*.png",
		"*.jpg",
		"*.jpeg",
		"*.gif",
		"*.ico",
		"*.svg",
		"*.webp",

		// Documents & Archives
		"*.pdf",
		"*.zip",
		"*.tar",
		"*.gz",
		"*.bz2",
		"*.xz",
		"*.7z",
		"*.rar",

		// Compiled / Binary
		"*.exe",
		"*.dll",
		"*.so",
		"*.dylib",
		"*.pyc",
		"*.o",
		"*.a",
		"*.wasm",

		// Fonts & Media
		"*.woff",
		"*.woff2",
		"*.ttf",
		"*.eot",
		"*.mp3",
		"*.mp4",
		"*.avi",

		// Test files (contain intentional fake secrets as fixtures)
		"*_test.go",
		"*_test.py",
		"*_test.js",
		"*_test.ts",
		"*.test.js",
		"*.test.ts",
		"*.spec.js",
		"*.spec.ts",
		"*_test.rb",
		"*_test.rs",
	}
}

// NewIgnoreMatcher creates a matcher from default patterns and optional .leakscanner-ignore file.
func NewIgnoreMatcher(ignoreFilePath string) *IgnoreMatcher {
	matcher := &IgnoreMatcher{
		patterns: DefaultIgnorePatterns(),
	}

	if ignoreFilePath != "" {
		if file, err := os.Open(ignoreFilePath); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					matcher.patterns = append(matcher.patterns, line)
				}
			}
		}
	}

	return matcher
}

// ShouldIgnore returns true if path matches any ignore pattern.
func (im *IgnoreMatcher) ShouldIgnore(path string) bool {
	// Normalize path separators to forward slash for consistent matching
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	parts := strings.Split(cleanPath, "/")

	for _, pattern := range im.patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		pattern = strings.TrimPrefix(pattern, "./")

		// Check directory component exact match
		for _, part := range parts {
			if part == strings.TrimSuffix(pattern, "/*") || part == strings.TrimSuffix(pattern, "/") {
				return true
			}
		}

		// Glob match on relative path or basename
		matched, _ := filepath.Match(pattern, cleanPath)
		if matched {
			return true
		}
		base := filepath.Base(cleanPath)
		matchedBase, _ := filepath.Match(pattern, base)
		if matchedBase {
			return true
		}
	}

	return false
}
