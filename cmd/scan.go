package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"leakscan/internal/config"
	"leakscan/internal/detector"
	"leakscan/internal/report"
	"leakscan/internal/scanner"
	"leakscan/rules"
)

var (
	includeGitHistory bool
	includeShell      bool
	includeProcess    bool
	entropyThreshold  float64
	formatFlag        string
	ignoreFileFlag    string
	failSeverityFlag  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan target path for leaked secrets",
	Long:  `Scans the specified filesystem directory (default '.') for leaked secret tokens, API keys, credentials, and configuration files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		// 1. Load Rules
		ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
		if err != nil {
			return fmt.Errorf("failed to load default rules: %w", err)
		}

		regexDet, err := detector.NewRegexDetector(ruleSet)
		if err != nil {
			return fmt.Errorf("failed to compile regex rules: %w", err)
		}

		detectors := []detector.Detector{regexDet}

		// Add entropy detector if configured
		if entropyThreshold > 0 {
			entropyDet := detector.NewEntropyDetector(entropyThreshold)
			detectors = append(detectors, entropyDet)
		}

		// 2. Load Ignore Config
		ignoreMatcher := config.NewIgnoreMatcher(ignoreFileFlag)

		// 3. Register Scanners
		var scanners []detector.Scanner
		scanners = append(scanners, scanner.NewFilesystemScanner(targetPath, detectors, ignoreMatcher))

		if includeGitHistory {
			scanners = append(scanners, scanner.NewGitScanner(targetPath, detectors, ignoreMatcher))
		}

		if includeShell {
			scanners = append(scanners, scanner.NewShellHistoryScanner(detectors))
		}

		if includeProcess {
			scanners = append(scanners, scanner.NewProcessScanner(detectors))
		}

		// 4. Run Scan
		ctx := context.Background()
		var allFindings []detector.Finding

		for _, s := range scanners {
			findings, err := s.Scan(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Scanner '%s' returned error: %v\n", s.Name(), err)
			}
			allFindings = append(allFindings, findings...)
		}

		// 5. Deduplicate findings by (source, location, redacted value)
		allFindings = deduplicateFindings(allFindings)

		// 6. Report Findings
		if formatFlag == "json" {
			if err := report.PrintJSONReport(os.Stdout, allFindings); err != nil {
				return err
			}
		} else {
			report.PrintTerminalReport(os.Stdout, allFindings)
		}

		// 7. Handle Fail Severity Exit Code
		if shouldFail(allFindings, failSeverityFlag) {
			return fmt.Errorf("leakscan detected findings at or above '%s' severity", failSeverityFlag)
		}

		return nil
	},
}

func shouldFail(findings []detector.Finding, failSev string) bool {
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

// deduplicateFindings removes duplicate findings based on (source, location, redacted) composite key.
func deduplicateFindings(findings []detector.Finding) []detector.Finding {
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

func init() {
	scanCmd.Flags().BoolVar(&includeGitHistory, "include-git-history", false, "Scan full git commit history in repository")
	scanCmd.Flags().BoolVar(&includeShell, "include-shell-history", false, "Scan local shell history (~/.bash_history, ~/.zsh_history)")
	scanCmd.Flags().BoolVar(&includeProcess, "include-process-env", false, "Scan running process environment variables")
	scanCmd.Flags().Float64Var(&entropyThreshold, "entropy-threshold", 3.8, "Shannon entropy threshold for high-entropy string detection (0 to disable)")
	scanCmd.Flags().StringVar(&formatFlag, "format", "terminal", "Output format: 'terminal' or 'json'")
	scanCmd.Flags().StringVar(&ignoreFileFlag, "ignore-file", ".leakscanner-ignore", "Path to ignore file")
	scanCmd.Flags().StringVar(&failSeverityFlag, "fail-severity", "none", "Exit non-zero if findings exist at or above severity ('critical', 'high', 'medium', 'none')")

	rootCmd.AddCommand(scanCmd)
}
