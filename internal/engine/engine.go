// Package engine provides the shared scan orchestrator for leakscan.
// All commands (scan, tui, watch) call engine.Run() to execute
// the full scan pipeline in a single, non-duplicated code path.
package engine

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"leakscan/internal/config"
	"leakscan/internal/detector"
	"leakscan/internal/scanner"
	"leakscan/rules"
)

// Config holds all parameters needed to execute a scan.
type Config struct {
	TargetPath       string
	IncludeStaged    bool
	IncludeGit       bool
	IncludeShell     bool
	IncludeProcess   bool
	EntropyThreshold float64
	RulesFile        string
	IgnoreFile       string
	MaxFileSize      int64 // Skip files larger than this (bytes). 0 = no limit.
}

// Result holds the output of a completed scan.
type Result struct {
	Findings []detector.Finding
	Duration time.Duration
}

// Run executes the full scan pipeline:
//  1. Load default + custom rules
//  2. Build detectors (regex + entropy)
//  3. Register scanners based on config
//  4. Run all scanners in parallel via errgroup
//  5. Deduplicate findings
func Run(ctx context.Context, cfg Config) (*Result, error) {
	start := time.Now()

	// 1. Load Rules
	ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
	if err != nil {
		return nil, fmt.Errorf("failed to load default rules: %w", err)
	}

	// Merge custom rules if specified
	if cfg.RulesFile != "" {
		customData, err := os.ReadFile(cfg.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom rules file '%s': %w", cfg.RulesFile, err)
		}
		customRuleSet, err := detector.LoadRulesFromYAML(customData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse custom rules file '%s': %w", cfg.RulesFile, err)
		}
		ruleSet.Rules = append(ruleSet.Rules, customRuleSet.Rules...)
		fmt.Fprintf(os.Stderr, "✔ Loaded %d custom rule(s) from %s\n", len(customRuleSet.Rules), cfg.RulesFile)
	}

	// 2. Build Detectors
	regexDet, err := detector.NewRegexDetector(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex rules: %w", err)
	}

	detectors := []detector.Detector{regexDet}

	if cfg.EntropyThreshold > 0 {
		entropyDet := detector.NewEntropyDetector(cfg.EntropyThreshold)
		detectors = append(detectors, entropyDet)
	}

	// 3. Load Ignore Config
	ignoreMatcher := config.NewIgnoreMatcher(cfg.IgnoreFile)

	// 4. Register Scanners
	var scanners []detector.Scanner

	if cfg.IncludeStaged {
		// In staged mode, only scan staged changes in git index
		scanners = append(scanners, scanner.NewStagedScanner(cfg.TargetPath, detectors, ignoreMatcher))
	} else {
		// Standard filesystem scan
		fsScanner := scanner.NewFilesystemScanner(cfg.TargetPath, detectors, ignoreMatcher)
		if cfg.MaxFileSize > 0 {
			fsScanner.SetMaxFileSize(cfg.MaxFileSize)
		}
		scanners = append(scanners, fsScanner)
	}

	if cfg.IncludeGit {
		scanners = append(scanners, scanner.NewGitScanner(cfg.TargetPath, detectors, ignoreMatcher))
	}

	if cfg.IncludeShell {
		scanners = append(scanners, scanner.NewShellHistoryScanner(detectors))
	}

	if cfg.IncludeProcess {
		scanners = append(scanners, scanner.NewProcessScanner(detectors))
	}

	// 5. Run Scan (parallel execution)
	var allFindings []detector.Finding
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)
	for _, s := range scanners {
		g.Go(func() error {
			findings, err := s.Scan(gctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Scanner '%s' returned error: %v\n", s.Name(), err)
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
			return nil // Don't propagate — individual scanner errors are warnings
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// 6. Deduplicate findings
	allFindings = DeduplicateFindings(allFindings)

	return &Result{
		Findings: allFindings,
		Duration: time.Since(start),
	}, nil
}

// DeduplicateFindings removes duplicate findings based on (source, location, redacted) composite key.
func DeduplicateFindings(findings []detector.Finding) []detector.Finding {
	seen := make(map[string]bool)
	var unique []detector.Finding
	for _, f := range findings {
		key := f.Source + "|" + f.Location + "|" + f.Redacted
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

// ShouldFail returns true if any finding meets or exceeds the given severity threshold.
func ShouldFail(findings []detector.Finding, failSev string) bool {
	if failSev == "" || failSev == "none" {
		return false
	}

	targetLevel := 0
	switch failSev {
	case "critical":
		targetLevel = 3
	case "high":
		targetLevel = 2
	case "medium":
		targetLevel = 1
	default:
		return false
	}

	for _, f := range findings {
		fLevel := 0
		switch f.Severity {
		case "critical":
			fLevel = 3
		case "high":
			fLevel = 2
		case "medium":
			fLevel = 1
		}
		if fLevel >= targetLevel {
			return true
		}
	}
	return false
}
