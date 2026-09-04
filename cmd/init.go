package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"leakscan/internal/config"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold .leakscanner-ignore file and git pre-commit hook",
	Long:  `Initializes leakscan configuration in the current repository, creating a sample .leakscanner-ignore file and git pre-commit hook script.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Create .leakscanner-ignore
		ignoreFile := ".leakscanner-ignore"
		if _, err := os.Stat(ignoreFile); os.IsNotExist(err) {
			content := "# leakscan ignore patterns\n" +
				"# Add paths or glob patterns to ignore during secret scanning\n\n" +
				"node_modules/\n" +
				"vendor/\n" +
				"*.png\n" +
				"*.jpg\n" +
				"*.zip\n" +
				".git/\n" +
				"*.example\n" +
				"*.sample\n"
			for _, pat := range config.DefaultIgnorePatterns() {
				content += pat + "\n"
			}
			if err := os.WriteFile(ignoreFile, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to create %s: %w", ignoreFile, err)
			}
			fmt.Printf("✔ Created %s\n", ignoreFile)
		} else {
			fmt.Printf("ℹ %s already exists\n", ignoreFile)
		}

		// 2. Scaffold git pre-commit hook if .git exists
		gitHookDir := filepath.Join(".git", "hooks")
		if info, err := os.Stat(gitHookDir); err == nil && info.IsDir() {
			hookPath := filepath.Join(gitHookDir, "pre-commit")
			if _, err := os.Stat(hookPath); os.IsNotExist(err) {
				hookContent := `#!/bin/sh
# leakscan pre-commit hook
# Prevents committing secrets to git repository

echo "🔍 Running leakscan pre-commit security check (staged diffs)..."
leakscan scan --staged --fail-severity high

if [ $? -ne 0 ]; then
    echo "❌ Leakscan detected potential secret leaks in staged changes!"
    echo "Please remove secrets or rotate compromised credentials before committing."
    exit 1
fi
`
				if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
					return fmt.Errorf("failed to create git pre-commit hook at %s: %w", hookPath, err)
				}
				fmt.Printf("✔ Scaffolded git pre-commit hook at %s\n", hookPath)
			} else {
				fmt.Printf("ℹ Pre-commit hook already exists at %s (skipped to avoid overwriting)\n", hookPath)
			}
		} else {
			fmt.Println("ℹ No .git directory detected; skipped pre-commit hook installation.")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
