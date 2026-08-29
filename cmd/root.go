package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"leakscan/internal/theme"
)


var rootCmd = &cobra.Command{
	Use:   "leakscan",
	Short: "⚡ Secrets & Credential Leak Scanner CLI",
	Long:  `A zero-leak local security scanner written in Go that inspects local filesystems, git history, shell history, and process environments with LazyVim TokyoNight aesthetics.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	cobra.AddTemplateFunc("styleHeader", func(s string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(theme.ColorPurple).Render(s)
	})
	cobra.AddTemplateFunc("styleCmd", func(s string) string {
		return lipgloss.NewStyle().Foreground(theme.ColorCyan).Bold(true).Render(s)
	})
	cobra.AddTemplateFunc("styleFlag", func(s string) string {
		return lipgloss.NewStyle().Foreground(theme.ColorBlue).Render(s)
	})

	rootCmd.SetHelpTemplate(lazyVimHelpTemplate())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func lazyVimHelpTemplate() string {
	logo := lipgloss.NewStyle().
		Bold(true).
		Foreground(theme.ColorBg).
		Background(theme.ColorPurple).
		Padding(0, 1).
		Render("⚡ LEAKSCAN CLI ⚡")

	title := lipgloss.NewStyle().Foreground(theme.ColorBlue).Bold(true).Render("LazyVim Modern Security Suite")
	footer := lipgloss.NewStyle().Foreground(theme.ColorDim).Italic(true).Render("󰌌  Type 'leakscan [command] --help' for details on a specific command.")

	return fmt.Sprintf(`
  %s  %s

{{styleHeader "USAGE:"}}
  {{styleCmd .UseLine}} [flags]

{{if .HasAvailableSubCommands}}{{styleHeader "COMMANDS:"}}
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad (styleCmd .Name) 20}} {{.Short}}
{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}{{styleHeader "FLAGS:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}

  %s
`, logo, title, footer)
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "Show per-file scan progress")
	rootCmd.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress all output except exit code")
}
