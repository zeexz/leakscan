package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"leakscan/internal/config"
	"leakscan/internal/engine"
	"leakscan/internal/report"
)

var (
	stagedFlag         bool
	includeGitHistory  bool
	includeShell       bool
	includeProcess     bool
	entropyThreshold   float64
	formatFlag         string
	ignoreFileFlag     string
	failSeverityFlag   string
	rulesFileFlag      string
	maxFileSizeFlag    int64
	verboseFlag        bool
	quietFlag          bool
	recordBaselineFlag string
	baselineFlag       string
	webhookURLFlag     string
	uploadURLFlag      string
	authTokenFlag      string
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

		// 1. Record baseline snapshot if requested
		if recordBaselineFlag != "" {
			if err := config.SaveBaseline(recordBaselineFlag, result.Findings); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}
			fmt.Fprintf(os.Stderr, "✔ Recorded %d finding(s) to baseline '%s'\n", len(result.Findings), recordBaselineFlag)
		}

		// 2. Filter against existing baseline if specified
		if baselineFlag != "" {
			baseline, err := config.LoadBaseline(baselineFlag)
			if err != nil {
				return fmt.Errorf("failed to load baseline: %w", err)
			}
			active, suppressed := config.FilterAgainstBaseline(result.Findings, baseline)
			if len(suppressed) > 0 {
				fmt.Fprintf(os.Stderr, "ℹ Suppressed %d existing finding(s) matching baseline '%s'\n", len(suppressed), baselineFlag)
			}
			result.Findings = active
		}

		// 3. Dispatch Webhook alert if requested and findings exist
		if webhookURLFlag != "" && len(result.Findings) > 0 {
			if err := report.SendWebhook(context.Background(), webhookURLFlag, result.Findings, authTokenFlag); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to dispatch webhook: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "✔ Dispatched alert to webhook '%s'\n", webhookURLFlag)
			}
		}

		// 4. Upload full report to remote ingestion server if requested
		if uploadURLFlag != "" {
			var uploadData bytes.Buffer
			contentType := "application/json"
			if formatFlag == "sarif" {
				_ = report.PrintSARIFReport(&uploadData, result.Findings)
				contentType = "application/sarif+json"
			} else {
				_ = report.PrintJSONReport(&uploadData, result.Findings)
			}
			if err := report.UploadReport(context.Background(), uploadURLFlag, contentType, uploadData.Bytes(), authTokenFlag); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to upload report to '%s': %v\n", uploadURLFlag, err)
			} else {
				fmt.Fprintf(os.Stderr, "✔ Uploaded scan report to '%s'\n", uploadURLFlag)
			}
		}

		// 5. Report Findings locally
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

		// 6. Handle Fail Severity Exit Code
		if engine.ShouldFail(result.Findings, failSeverityFlag) {
			// Exit code 2 = findings found (distinct from exit code 1 = scan error)
			fmt.Fprintf(os.Stderr, "leakscan: detected findings at or above '%s' severity\n", failSeverityFlag)
			os.Exit(2)
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&stagedFlag, "staged", false, "Scan only git staged changes (fast pre-commit check)")
	scanCmd.Flags().BoolVar(&includeGitHistory, "include-git-history", false, "Scan full git commit history in repository")
	scanCmd.Flags().BoolVar(&includeShell, "include-shell-history", false, "Scan local shell history (~/.bash_history, ~/.zsh_history)")
	scanCmd.Flags().BoolVar(&includeProcess, "include-process-env", false, "Scan running process environment variables")
	scanCmd.Flags().Float64Var(&entropyThreshold, "entropy-threshold", 3.8, "Shannon entropy threshold for high-entropy string detection (0 to disable)")
	scanCmd.Flags().StringVar(&formatFlag, "format", "terminal", "Output format: 'terminal', 'json', or 'sarif'")
	scanCmd.Flags().StringVar(&ignoreFileFlag, "ignore-file", ".leakscanner-ignore", "Path to ignore file")
	scanCmd.Flags().StringVar(&failSeverityFlag, "fail-severity", "none", "Exit non-zero if findings exist at or above severity ('critical', 'high', 'medium', 'none')")
	scanCmd.Flags().StringVar(&rulesFileFlag, "rules-file", "", "Path to additional custom rules YAML file to merge with defaults")
	scanCmd.Flags().Int64Var(&maxFileSizeFlag, "max-file-size", 0, "Skip files larger than this size in bytes (0 = no limit, e.g. 1048576 for 1MB)")
	scanCmd.Flags().StringVar(&recordBaselineFlag, "record-baseline", "", "Path to save baseline snapshot of current findings (e.g. .leakscan-baseline.json)")
	scanCmd.Flags().StringVar(&baselineFlag, "baseline", "", "Path to baseline file to suppress known existing findings")
	scanCmd.Flags().StringVar(&webhookURLFlag, "webhook-url", "", "Incoming webhook URL to dispatch alert notifications (Slack/Teams/Discord/Custom)")
	scanCmd.Flags().StringVar(&uploadURLFlag, "upload-url", "", "HTTP POST endpoint to upload full scan report (JSON or SARIF)")
	scanCmd.Flags().StringVar(&authTokenFlag, "auth-token", "", "Bearer token for webhook/upload authentication (or via LEAKSCAN_AUTH_TOKEN env)")

	rootCmd.AddCommand(scanCmd)
}
