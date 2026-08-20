package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"leakscan/internal/detector"
	"leakscan/internal/theme"
)

// Styles using centralized TokyoNight / LazyVim Color Palette
var (
	// Base Box & Header Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(theme.ColorBg).
			Background(theme.ColorPurple).
			Padding(0, 1)

	headerBannerStyle = lipgloss.NewStyle().
				Foreground(theme.ColorBlue).
				Bold(true)

	badgeCritical = lipgloss.NewStyle().
			Bold(true).
			Foreground(theme.ColorBg).
			Background(theme.ColorRed).
			Padding(0, 1)

	badgeHigh = lipgloss.NewStyle().
			Bold(true).
			Foreground(theme.ColorBg).
			Background(theme.ColorYellow).
			Padding(0, 1)

	badgeMedium = lipgloss.NewStyle().
			Bold(true).
			Foreground(theme.ColorBg).
			Background(theme.ColorCyan).
			Padding(0, 1)

	badgeSuccess = lipgloss.NewStyle().
			Bold(true).
			Foreground(theme.ColorBg).
			Background(theme.ColorGreen).
			Padding(0, 1)

	labelStyle = lipgloss.NewStyle().
			Foreground(theme.ColorPurple).
			Bold(true).
			Width(13)

	valueStyle = lipgloss.NewStyle().
			Foreground(theme.ColorFg)

	redactedStyle = lipgloss.NewStyle().
			Foreground(theme.ColorRed).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(theme.ColorDim)

	keyHintStyle = lipgloss.NewStyle().
			Foreground(theme.ColorComment).
			Italic(true)
)

// PrintTerminalReport outputs LazyVim modern styled findings to terminal
func PrintTerminalReport(w io.Writer, findings []detector.Finding) {
	// 1. Header Banner
	banner := []string{
		"  ⚡ LEAKSCAN — Secrets & Credential Detector ⚡",
	}
	header := headerBannerStyle.Render(strings.Join(banner, "\n"))
	fmt.Fprintln(w, header)
	fmt.Fprintln(w)

	if len(findings) == 0 {
		emptyBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(theme.ColorGreen).
			Padding(1, 2).
			Render(fmt.Sprintf("%s  No secret leaks detected! Your workspace is safe.", badgeSuccess.Render("✔ CLEAN")))
		fmt.Fprintln(w, emptyBox)
		fmt.Fprintln(w)
		return
	}

	var criticals, highs, mediums []detector.Finding
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			criticals = append(criticals, f)
		case "high":
			highs = append(highs, f)
		default:
			mediums = append(mediums, f)
		}
	}

	// Stats Summary Pill Bar
	statsBar := fmt.Sprintf(
		" %s  Total Leaks: %s │ %s %d  │ %s %d  │ %s %d",
		titleStyle.Render("SCAN RESULTS"),
		lipgloss.NewStyle().Foreground(theme.ColorBlue).Bold(true).Render(fmt.Sprintf("%d", len(findings))),
		badgeCritical.Render("CRITICAL"), len(criticals),
		badgeHigh.Render("HIGH"), len(highs),
		badgeMedium.Render("MEDIUM"), len(mediums),
	)
	fmt.Fprintln(w, statsBar)
	fmt.Fprintln(w)

	idx := 1
	renderGroup := func(groupTitle string, badgeStyle lipgloss.Style, list []detector.Finding, borderColor lipgloss.Color) {
		if len(list) == 0 {
			return
		}

		groupHeader := badgeStyle.Render(fmt.Sprintf(" %s (%d) ", groupTitle, len(list)))
		fmt.Fprintln(w, groupHeader)

		for _, f := range list {
			var cardBuilder strings.Builder

			itemTitle := lipgloss.NewStyle().Foreground(theme.ColorBlue).Bold(true).Render(fmt.Sprintf("#%d %s", idx, f.Type))
			cardBuilder.WriteString(fmt.Sprintf("%s\n", itemTitle))
			cardBuilder.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("  Source:"), valueStyle.Render(f.Source)))
			cardBuilder.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("  Location:"), valueStyle.Render(f.Location)))
			cardBuilder.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("  Redacted:"), redactedStyle.Render(f.Redacted)))
			cardBuilder.WriteString(fmt.Sprintf("%s %s", labelStyle.Render("  Remediation:"), dimStyle.Render(f.Remediation)))

			box := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Padding(0, 1).
				Render(cardBuilder.String())

			fmt.Fprintln(w, box)
			idx++
		}
	}

	renderGroup("CRITICAL LEAKS", badgeCritical, criticals, theme.ColorRed)
	renderGroup("HIGH SEVERITY", badgeHigh, highs, theme.ColorYellow)
	renderGroup("MEDIUM SEVERITY", badgeMedium, mediums, theme.ColorCyan)

	// LazyVim Footer status line hint
	footer := lipgloss.NewStyle().
		Foreground(theme.ColorComment).
		Render("────── 󰌌  Use --format json for machine readable output | --fail-severity high for CI/CD gates ──────")
	fmt.Fprintln(w, footer)
	fmt.Fprintln(w)
}
