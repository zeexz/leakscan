package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"leakscan/internal/config"
	"strings"
)

func TestStagedScanner_DetectsStagedSecret(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Create initial commit with clean file
	readmeFile := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmeFile, []byte("# Test Repo\nInitial clean file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatal(err)
	}
	_, err = wt.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Stage a file with an AWS secret
	stagedSecretFile := filepath.Join(dir, "credentials.txt")
	secretContent := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	if err := os.WriteFile(stagedSecretFile, []byte(secretContent), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("credentials.txt"); err != nil {
		t.Fatal(err)
	}

	// 2. Also write an unstaged secret in another file (should NOT be detected by staged scanner)
	unstagedFile := filepath.Join(dir, "unstaged.txt")
	if err := os.WriteFile(unstagedFile, []byte("AWS_KEY=AKIAIOSFODNN7UNSTAGED\n"), 0644); err != nil {
		t.Fatal(err)
	}

	detectors := gitTestDetectors(t)
	matcher := config.NewIgnoreMatcher("")
	s := NewStagedScanner(dir, detectors, matcher)

	if s.Name() != "git-staged" {
		t.Errorf("expected scanner name 'git-staged', got %q", s.Name())
	}

	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Staged scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected findings in staged file, got 0")
	}

	for _, f := range findings {
		if f.Location != "credentials.txt:1" && !filepath.IsAbs(f.Location) {
			// Location might have (author: , date: ) suffix
			if !strings.HasPrefix(f.Location, "credentials.txt:1") {
				t.Errorf("expected finding in credentials.txt:1, got %s", f.Location)
			}
		}
		if strings.Contains(f.Location, "unstaged.txt") {
			t.Errorf("unstaged file should not be detected, but found in: %s", f.Location)
		}
	}
}

func TestStagedScanner_NonGitDirectory(t *testing.T) {
	dir := t.TempDir()
	detectors := gitTestDetectors(t)
	matcher := config.NewIgnoreMatcher("")
	s := NewStagedScanner(dir, detectors, matcher)

	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error for non-git directory: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
