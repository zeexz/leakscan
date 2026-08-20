package cmd

import (
	"context"
	"fmt"

	"time"

	"github.com/spf13/cobra"
	"leakscan/internal/config"
	"leakscan/internal/detector"
	"leakscan/internal/report"
	"leakscan/internal/scanner"
	"leakscan/rules"
)

var watchCmd = &cobra.Command{
	Use:   "watch [path]",
	Short: "Continuously watch a directory for real-time secret leaks",
	Long:  `Monitors specified filesystem directory for file modifications and automatically triggers leak scanning on changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		fmt.Printf("👀 Starting leakscan live watcher on '%s' (press Ctrl+C to stop)...\n\n", targetPath)

		ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
		if err != nil {
			return err
		}

		regexDet, err := detector.NewRegexDetector(ruleSet)
		if err != nil {
			return err
		}

		detectors := []detector.Detector{regexDet}
		if entropyThreshold > 0 {
			detectors = append(detectors, detector.NewEntropyDetector(entropyThreshold))
		}

		ignoreMatcher := config.NewIgnoreMatcher(ignoreFileFlag)
		fsScanner := scanner.NewFilesystemScanner(targetPath, detectors, ignoreMatcher)

		// Polling watcher loop for continuous monitoring across platforms
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		runScan := func() {
			fmt.Printf("[%s] Running scan...\n", time.Now().Format("15:04:05"))
			findings, err := fsScanner.Scan(context.Background())
			if err != nil {
				fmt.Printf("Scan error: %v\n", err)
				return
			}
			report.PrintTerminalReport(cmd.OutOrStdout(), findings)
		}

		runScan()

		for range ticker.C {
			runScan()
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(watchCmd)
}
