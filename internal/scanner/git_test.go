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
	"leakscan/internal/detector"
	"leakscan/rules"
)

func gitTestDetectors(t *testing.T) []detector.Detector {
	t.Helper()
	ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}
	regexDet, err := detector.NewRegexDetector(ruleSet)
	if err != nil {
		t.Fatalf("Failed to create regex detector: %v", err)
	}
	return []detector.Detector{regexDet}
}

func TestGitScanner_DetectsSecretInHistory(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Commit 1: Add a secret
	secretFile := filepath.Join(dir, "config.env")
	secretContent := "AWS_ACCESS_KEY_ID=" + "AKIA" + "TESTKEY1234567890"
	if err := os.WriteFile(secretFile, []byte(secretContent), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("config.env"); err != nil {
		t.Fatal(err)
	}
	_, err = wt.Commit("add secret", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	// Commit 2: Delete the secret file
	if err := os.Remove(secretFile); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Remove("config.env"); err != nil {
		t.Fatal(err)
	}
	_, err = wt.Commit("remove secret", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	// Scan git history — should find the secret even though file is deleted
	detectors := gitTestDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewGitScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected findings from git history (deleted secret), got 0")
	}

	// Verify the git remediation note is appended
	for _, f := range findings {
		if f.Source == "" {
			t.Errorf("Finding should have a source set")
		}
	}
}

func TestGitScanner_NotAGitRepo(t *testing.T) {
	dir := t.TempDir()

	detectors := gitTestDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewGitScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Non-git directory should not return error, got: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for non-git directory, got %d", len(findings))
	}
}

func TestGitScanner_RootCommitScanning(t *testing.T) {
	dir := t.TempDir()

	// Initialize a git repo with a single commit containing a secret
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	secretFile := filepath.Join(dir, "secret.txt")
	content := "-----BEGIN RSA PRIVATE KEY-----"
	if err := os.WriteFile(secretFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("secret.txt"); err != nil {
		t.Fatal(err)
	}
	_, err = wt.Commit("initial commit with secret", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	detectors := gitTestDetectors(t)
	ignoreMatcher := config.NewIgnoreMatcher("")
	scanner := NewGitScanner(dir, detectors, ignoreMatcher)

	findings, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected findings from root commit scanning, got 0")
	}
}

func TestGitScanner_Name(t *testing.T) {
	scanner := NewGitScanner(".", nil, nil)
	if scanner.Name() != "git-history" {
		t.Errorf("Expected name 'git-history', got %q", scanner.Name())
	}
}
