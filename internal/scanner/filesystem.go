package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"leakscan/internal/config"
	"leakscan/internal/detector"
)

// FilesystemScanner walks directories scanning files for secrets.
type FilesystemScanner struct {
	rootDir       string
	detectors     []detector.Detector
	ignoreMatcher *config.IgnoreMatcher
	maxFileSize   int64 // Skip files larger than this (bytes). 0 = no limit.
}

// NewFilesystemScanner creates a new FilesystemScanner instance.
func NewFilesystemScanner(rootDir string, detectors []detector.Detector, ignoreMatcher *config.IgnoreMatcher) *FilesystemScanner {
	if rootDir == "" {
		rootDir = "."
	}
	if ignoreMatcher == nil {
		ignoreMatcher = config.NewIgnoreMatcher("")
	}
	return &FilesystemScanner{
		rootDir:       rootDir,
		detectors:     detectors,
		ignoreMatcher: ignoreMatcher,
	}
}

// SetMaxFileSize configures the maximum file size in bytes. Files larger than
// this are skipped to prevent OOM on large binaries/logs. 0 means no limit.
func (s *FilesystemScanner) SetMaxFileSize(size int64) {
	s.maxFileSize = size
}

func (s *FilesystemScanner) Name() string {
	return "filesystem"
}

func (s *FilesystemScanner) Scan(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	err := filepath.Walk(s.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip unreadable paths
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		relPath, _ := filepath.Rel(s.rootDir, path)
		if relPath == "" {
			relPath = path
		}

		if s.ignoreMatcher.ShouldIgnore(relPath) || s.ignoreMatcher.ShouldIgnore(path) {
			if info.IsDir() && relPath != "." && relPath != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// 1. Check file permission issues for sensitive file names
		if isSensitiveFilename(path) {
			if isWorldReadable(info) {
				findings = append(findings, detector.Finding{
					Source:      fmt.Sprintf("file:%s", path),
					Type:        "Insecure World-Readable File Permission",
					Location:    fmt.Sprintf("%s (mode %o)", path, info.Mode().Perm()),
					Severity:    "medium",
					Redacted:    "[FILE PERMISSION ISSUE]",
					Remediation: fmt.Sprintf("Restrict file permissions on %s (e.g. chmod 600 %s).", path, path),
				})
			}
		}

		// 2. Skip files exceeding max file size (prevents OOM on large logs/binaries)
		if s.maxFileSize > 0 && info.Size() > s.maxFileSize {
			return nil
		}

		// 3. Read content and run detectors
		contentBytes, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil // Skip files that cannot be read (binary locked, permission denied, etc.)
		}

		// Skip binary files (quick zero-byte check)
		if isBinary(contentBytes) {
			return nil
		}

		content := string(contentBytes)
		meta := detector.SourceMeta{
			Type: "file",
			Path: relPath,
		}

		for _, d := range s.detectors {
			found := d.Detect(content, meta)
			findings = append(findings, found...)
		}

		return nil
	})

	if err != nil && err != context.Canceled {
		return findings, fmt.Errorf("filesystem walk error: %w", err)
	}

	return findings, nil
}

func isSensitiveFilename(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, ".env") || base == "credentials" || strings.HasPrefix(base, "id_") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return true
	}
	return false
}

func isWorldReadable(info os.FileInfo) bool {
	// Unix permission bits are meaningless on Windows; skip the check.
	if runtime.GOOS == "windows" {
		return false
	}
	// On Unix, check world-read bit (0004)
	perm := info.Mode().Perm()
	return (perm & 0004) != 0
}

func isBinary(data []byte) bool {
	limit := 1024
	if len(data) < limit {
		limit = len(data)
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}
