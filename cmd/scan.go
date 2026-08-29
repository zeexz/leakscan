package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"leakscan/internal/engine"
	"leakscan/internal/report"
)

var (
	includeGitHistory bool
	includeShell      bool
	includeProcess    bool
	entropyThreshold  float64
	formatFlag        string
	ignoreFileFlag    string
	failSeverityFlag  string
	rulesFileFlag     string
	maxFileSizeFlag   int64
	verboseFlag       bool
	quietFlag         bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan target path for leaked secrets",
	Long:  `Scans the specified filesystem directory (default '.') for leaked secret tokens, API keys, credentials, and configuration files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := buildConfig(args)

		// Run the shared scan pipeline
		result, err := engine.Run(context.Background(), cfg)
		if err != nil {
			return err
		}

		// Report Findings
		if !quietFlag {
			switch formatFlag {
			case "json":
				if err := report.PrintJSONReport(os.Stdout, result.Findings); err != nil {
					return err
				}
			case "sarif":
				if err := report.PrintSARIFReport(os.Stdout, result.Findings); err != nil {
					return err
				}
			default:
				report.PrintTerminalReport(os.Stdout, result.Findings)
			}
		}

		// Handle Fail Severity Exit Code
		if engine.ShouldFail(result.Findings, failSeverityFlag) {
			// Exit code 2 = findings found (distinct from exit code 1 = scan error)
			fmt.Fprintf(os.Stderr, "leakscan: detected findings at or above '%s' severity\n", failSeverityFlag)
			os.Exit(2)
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&includeGitHistory, "include-git-history", false, "Scan full git commit history in repository")
	scanCmd.Flags().BoolVar(&includeShell, "include-shell-history", false, "Scan local shell history (~/.bash_history, ~/.zsh_history)")
	scanCmd.Flags().BoolVar(&includeProcess, "include-process-env", false, "Scan running process environment variables")
	scanCmd.Flags().Float64Var(&entropyThreshold, "entropy-threshold", 3.8, "Shannon entropy threshold for high-entropy string detection (0 to disable)")
	scanCmd.Flags().StringVar(&formatFlag, "format", "terminal", "Output format: 'terminal', 'json', or 'sarif'")
	scanCmd.Flags().StringVar(&ignoreFileFlag, "ignore-file", ".leakscanner-ignore", "Path to ignore file")
	scanCmd.Flags().StringVar(&failSeverityFlag, "fail-severity", "none", "Exit non-zero if findings exist at or above severity ('critical', 'high', 'medium', 'none')")
	scanCmd.Flags().StringVar(&rulesFileFlag, "rules-file", "", "Path to additional custom rules YAML file to merge with defaults")
	scanCmd.Flags().Int64Var(&maxFileSizeFlag, "max-file-size", 0, "Skip files larger than this size in bytes (0 = no limit, e.g. 1048576 for 1MB)")

	rootCmd.AddCommand(scanCmd)
}
