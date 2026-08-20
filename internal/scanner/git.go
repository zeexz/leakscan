package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"leakscan/internal/config"
	"leakscan/internal/detector"
)

// GitScanner inspects every historical commit in a git repository.
type GitScanner struct {
	repoPath      string
	detectors     []detector.Detector
	ignoreMatcher *config.IgnoreMatcher
}

// NewGitScanner creates a GitScanner instance.
func NewGitScanner(repoPath string, detectors []detector.Detector, ignoreMatcher *config.IgnoreMatcher) *GitScanner {
	if repoPath == "" {
		repoPath = "."
	}
	return &GitScanner{
		repoPath:      repoPath,
		detectors:     detectors,
		ignoreMatcher: ignoreMatcher,
	}
}

func (s *GitScanner) Name() string {
	return "git-history"
}

func (s *GitScanner) Scan(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	repo, err := git.PlainOpen(s.repoPath)
	if err != nil {
		// Not a git repository, return empty findings gracefully
		return findings, nil
	}

	repoName := filepath.Base(s.repoPath)
	if repoName == "." || repoName == "" {
		if abs, err := filepath.Abs(s.repoPath); err == nil {
			repoName = filepath.Base(abs)
		}
	}

	cIter, err := repo.Log(&git.LogOptions{All: true})
	if err != nil {
		return findings, fmt.Errorf("failed to fetch git commit history: %w", err)
	}

	seenCommits := make(map[string]bool)

	err = cIter.ForEach(func(c *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sha := c.Hash.String()
		if seenCommits[sha] {
			return nil
		}
		seenCommits[sha] = true

		shortSHA := sha
		if len(shortSHA) > 8 {
			shortSHA = shortSHA[:8]
		}

		authorStr := fmt.Sprintf("%s <%s>", c.Author.Name, c.Author.Email)
		dateStr := c.Author.When.Format("2006-01-02 15:04:05")

		// If commit has no parents (root commit), scan files directly
		if c.NumParents() == 0 {
			tree, err := c.Tree()
			if err != nil {
				return nil
			}
			_ = tree.Files().ForEach(func(f *object.File) error {
				if s.ignoreMatcher != nil && s.ignoreMatcher.ShouldIgnore(f.Name) {
					return nil
				}
				content, err := f.Contents()
				if err != nil {
					return nil
				}
				meta := detector.SourceMeta{
					Type:       "git",
					Path:       f.Name,
					RepoName:   repoName,
					CommitSHA:  shortSHA,
					Author:     authorStr,
					CommitDate: dateStr,
				}
				for _, d := range s.detectors {
					found := d.Detect(content, meta)
					for _, item := range found {
						item.Remediation += " Note: Leak is in Git history! Deleting the file is NOT sufficient. Rewrite history using 'git filter-repo' or 'BFG Repo-Cleaner', and consider the secret compromised."
						findings = append(findings, item)
					}
				}
				return nil
			})
			return nil
		}

		// Diff against first parent
		parent, err := c.Parent(0)
		if err != nil {
			return nil
		}

		patch, err := parent.Patch(c)
		if err != nil {
			return nil
		}

		for _, filePatch := range patch.FilePatches() {
			from, to := filePatch.Files()
			filePath := ""
			if to != nil {
				filePath = to.Path()
			} else if from != nil {
				filePath = from.Path()
			}

			if filePath == "" || (s.ignoreMatcher != nil && s.ignoreMatcher.ShouldIgnore(filePath)) {
				continue
			}

			for _, chunk := range filePatch.Chunks() {
				// Only scan added lines (+)
				if chunk.Type() == 1 { // diff.Add = 1 (added lines only)
					addedContent := chunk.Content()
					meta := detector.SourceMeta{
						Type:       "git",
						Path:       filePath,
						RepoName:   repoName,
						CommitSHA:  shortSHA,
						Author:     authorStr,
						CommitDate: dateStr,
					}
					for _, d := range s.detectors {
						found := d.Detect(addedContent, meta)
						for _, item := range found {
							if !strings.Contains(item.Remediation, "git filter-repo") {
								item.Remediation += " Note: Leak is in Git history! Deleting the file is NOT sufficient. Rewrite history using 'git filter-repo' or 'BFG Repo-Cleaner', and consider the secret compromised."
							}
							findings = append(findings, item)
						}
					}
				}
			}
		}

		return nil
	})

	if err != nil && err != context.Canceled {
		return findings, fmt.Errorf("error iterating git commits: %w", err)
	}

	return findings, nil
}
