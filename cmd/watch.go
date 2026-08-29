package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"leakscan/internal/engine"
	"leakscan/internal/report"
)

var watchCmd = &cobra.Command{
	Use:   "watch [path]",
	Short: "Continuously watch a directory for real-time secret leaks",
	Long:  `Monitors specified filesystem directory for file modifications and automatically triggers leak scanning on changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := buildConfig(args)

		fmt.Printf("👀 Starting leakscan live watcher on '%s' (press Ctrl+C to stop)...\n\n", cfg.TargetPath)

		// Graceful shutdown via signal handling
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		// Track previous findings to avoid reprinting duplicates
		prevFindingKeys := make(map[string]bool)

		runScan := func() {
			fmt.Printf("[%s] Running scan...\n", time.Now().Format("15:04:05"))
			result, err := engine.Run(ctx, cfg)
			if err != nil {
				fmt.Printf("Scan error: %v\n", err)
				return
			}

			// Check if findings changed since last scan
			currentKeys := make(map[string]bool)
			hasNew := false
			for _, f := range result.Findings {
				key := f.Source + "|" + f.Location + "|" + f.Redacted
				currentKeys[key] = true
				if !prevFindingKeys[key] {
					hasNew = true
				}
			}

			if hasNew || len(result.Findings) != len(prevFindingKeys) {
				report.PrintTerminalReport(cmd.OutOrStdout(), result.Findings)
				prevFindingKeys = currentKeys
			} else {
				fmt.Printf("[%s] No new findings (total: %d)\n", time.Now().Format("15:04:05"), len(result.Findings))
			}
		}

		// Initial scan
		runScan()

		// Polling loop with graceful shutdown
		for {
			select {
			case <-ctx.Done():
				fmt.Println("\n🛑 Watcher stopped gracefully.")
				return nil
			case <-ticker.C:
				runScan()
			}
		}
	},
}

func init() {
	watchCmd.Flags().BoolVar(&includeGitHistory, "include-git-history", false, "Scan full git commit history in repository")
	watchCmd.Flags().BoolVar(&includeShell, "include-shell-history", false, "Scan local shell history (~/.bash_history, ~/.zsh_history)")
	watchCmd.Flags().BoolVar(&includeProcess, "include-process-env", false, "Scan running process environment variables")
	watchCmd.Flags().Float64Var(&entropyThreshold, "entropy-threshold", 3.8, "Shannon entropy threshold for high-entropy string detection (0 to disable)")
	watchCmd.Flags().StringVar(&ignoreFileFlag, "ignore-file", ".leakscanner-ignore", "Path to ignore file")
	watchCmd.Flags().StringVar(&rulesFileFlag, "rules-file", "", "Path to additional custom rules YAML file to merge with defaults")
	watchCmd.Flags().Int64Var(&maxFileSizeFlag, "max-file-size", 0, "Skip files larger than this size in bytes (0 = no limit)")
	rootCmd.AddCommand(watchCmd)
}
