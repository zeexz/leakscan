package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"leakscan/internal/config"
	"leakscan/internal/detector"
)

var hunkHeaderRegex = regexp.MustCompile(`^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@`)

// StagedScanner inspects only git-staged changes (index) in the repository.
// This is specifically optimized for sub-second pre-commit checks.
type StagedScanner struct {
	repoPath      string
	detectors     []detector.Detector
	ignoreMatcher *config.IgnoreMatcher
}

// NewStagedScanner creates a StagedScanner instance.
func NewStagedScanner(repoPath string, detectors []detector.Detector, ignoreMatcher *config.IgnoreMatcher) *StagedScanner {
	if repoPath == "" {
		repoPath = "."
	}
	return &StagedScanner{
		repoPath:      repoPath,
		detectors:     detectors,
		ignoreMatcher: ignoreMatcher,
	}
}

func (s *StagedScanner) Name() string {
	return "git-staged"
}

func (s *StagedScanner) Scan(ctx context.Context) ([]detector.Finding, error) {
	// First attempt using git CLI for precise line-level staged diffs
	findings, err := s.scanWithGitCLI(ctx)
	if err == nil {
		return findings, nil
	}

	// Fallback to go-git if git command is unavailable
	return s.scanWithGoGit(ctx)
}

func (s *StagedScanner) scanWithGitCLI(ctx context.Context) ([]detector.Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "-U0")
	cmd.Dir = s.repoPath

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached failed: %w", err)
	}

	repoName := filepath.Base(s.repoPath)
	if repoName == "." || repoName == "" {
		if abs, err := filepath.Abs(s.repoPath); err == nil {
			repoName = filepath.Base(abs)
		}
	}

	return s.parseDiffOutput(out, repoName)
}

func (s *StagedScanner) parseDiffOutput(diffData []byte, repoName string) ([]detector.Finding, error) {
	var findings []detector.Finding
	scanner := bufio.NewScanner(bytes.NewReader(diffData))

	var currentFile string
	var currentLine int

	for scanner.Scan() {
		line := scanner.Text()

		// Match diff header to identify target file
		if strings.HasPrefix(line, "+++ ") {
			target := strings.TrimPrefix(line, "+++ ")
			if target == "/dev/null" {
				currentFile = ""
			} else {
				currentFile = strings.TrimPrefix(target, "b/")
			}
			continue
		}

		// Match hunk header: @@ -1,1 +10,5 @@
		if strings.HasPrefix(line, "@@ ") {
			matches := hunkHeaderRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				startLine, err := strconv.Atoi(matches[1])
				if err == nil {
					currentLine = startLine
				}
			}
			continue
		}

		// Added line in diff
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			if currentFile != "" {
				if s.ignoreMatcher != nil && s.ignoreMatcher.ShouldIgnore(currentFile) {
					currentLine++
					continue
				}

				content := strings.TrimPrefix(line, "+")
				meta := detector.SourceMeta{
					Type:       "git",
					Path:       currentFile,
					LineNumber: currentLine,
					RepoName:   repoName,
					CommitSHA:  "staged",
				}

				for _, d := range s.detectors {
					found := d.Detect(content, meta)
					for _, item := range found {
						item.Remediation += " Note: This leak is in your staged changes. Unstage or fix it before committing (e.g. 'git restore --staged <file>')."
						findings = append(findings, item)
					}
				}
			}
			currentLine++
		}
	}

	return findings, nil
}

// scanWithGoGit provides pure Go fallback to read staged blobs via go-git.
func (s *StagedScanner) scanWithGoGit(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	repo, err := git.PlainOpen(s.repoPath)
	if err != nil {
		return findings, nil // Graceful if not a git repository
	}

	wt, err := repo.Worktree()
	if err != nil {
		return findings, nil
	}

	status, err := wt.Status()
	if err != nil {
		return findings, nil
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return findings, nil
	}

	repoName := filepath.Base(s.repoPath)
	if repoName == "." || repoName == "" {
		if abs, err := filepath.Abs(s.repoPath); err == nil {
			repoName = filepath.Base(abs)
		}
	}

	for _, entry := range idx.Entries {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		fStatus := status.File(entry.Name)
		// Only inspect files staged for addition or modification
		if fStatus.Staging != git.Added && fStatus.Staging != git.Modified {
			continue
		}

		if s.ignoreMatcher != nil && s.ignoreMatcher.ShouldIgnore(entry.Name) {
			continue
		}

		blob, err := repo.BlobObject(entry.Hash)
		if err != nil {
			continue
		}

		reader, err := blob.Reader()
		if err != nil {
			continue
		}

		contentBytes, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			continue
		}

		meta := detector.SourceMeta{
			Type:      "git",
			Path:      entry.Name,
			RepoName:  repoName,
			CommitSHA: "staged",
		}

		for _, d := range s.detectors {
			found := d.Detect(string(contentBytes), meta)
			for _, item := range found {
				item.Remediation += " Note: This leak is in your staged changes. Unstage or fix it before committing (e.g. 'git restore --staged <file>')."
				findings = append(findings, item)
			}
		}
	}

	return findings, nil
}
