package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
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
	Long:  `Monitors specified filesystem directory for file changes using OS-native events and automatically triggers leak scanning on modifications.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		// Graceful shutdown via signal handling
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

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

		// Create fsnotify watcher
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create file watcher: %w", err)
		}
		defer watcher.Close()

		// Recursively add directories to watch
		if err := addWatchRecursive(watcher, targetPath, ignoreMatcher); err != nil {
			return fmt.Errorf("failed to watch directory tree: %w", err)
		}

		// Build scanner for on-demand rescans
		fsScanner := scanner.NewFilesystemScanner(targetPath, detectors, ignoreMatcher)

		// Run initial scan
		runWatchScan(cmd, fsScanner)

		// Debounce timer to batch rapid file changes (e.g., editor save-all)
		var debounceTimer *time.Timer
		var debounceMu sync.Mutex
		const debounceInterval = 500 * time.Millisecond

		triggerScan := func() {
			debounceMu.Lock()
			defer debounceMu.Unlock()
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debounceInterval, func() {
				runWatchScan(cmd, fsScanner)
			})
		}

		// Event loop
		for {
			select {
			case <-ctx.Done():
				fmt.Println("\n✔ Watcher stopped gracefully.")
				return nil

			case event, ok := <-watcher.Events:
				if !ok {
					return nil
				}

				// Only react to write, create, and rename events
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
					// If a new directory was created, add it to the watcher
					if event.Has(fsnotify.Create) {
						if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
							_ = addWatchRecursive(watcher, event.Name, ignoreMatcher)
						}
					}
					triggerScan()
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return nil
				}
				fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
			}
		}
	},
}

// runWatchScan executes a scan and prints results with a timestamp.
func runWatchScan(cmd *cobra.Command, fsScanner *scanner.FilesystemScanner) {
	fmt.Printf("[%s] Running scan...\n", time.Now().Format("15:04:05"))
	findings, err := fsScanner.Scan(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		return
	}
	report.PrintTerminalReport(cmd.OutOrStdout(), findings)
}

// addWatchRecursive walks the directory tree and adds each directory to the watcher.
func addWatchRecursive(watcher *fsnotify.Watcher, root string, ignoreMatcher *config.IgnoreMatcher) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip unreadable paths
		}
		if !info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		if relPath == "" {
			relPath = path
		}

		if ignoreMatcher != nil && ignoreMatcher.ShouldIgnore(relPath) && relPath != "." {
			return filepath.SkipDir
		}

		return watcher.Add(path)
	})
}

func init() {
	rootCmd.AddCommand(watchCmd)
}
