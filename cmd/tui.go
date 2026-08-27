package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"leakscan/internal/config"
	"leakscan/internal/detector"
	"leakscan/internal/scanner"
	"leakscan/rules"
)

type state int

const (
	stateHome state = iota
	stateScanning
	stateResults
)

type scanFinishedMsg struct {
	findings []detector.Finding
	err      error
}

type model struct {
	state      state
	targetPath string
	findings   []detector.Finding
	cursor     int
	status     string
	err        error
	width      int
	height     int
}

func initialModel(targetPath string) model {
	return model{
		state:      stateHome,
		targetPath: targetPath,
		status:     "Ready",
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func runScanCmd(targetPath string) tea.Cmd {
	return func() tea.Msg {
		ruleSet, err := detector.LoadRulesFromYAML(rules.DefaultPatternsYAML)
		if err != nil {
			return scanFinishedMsg{err: err}
		}

		// Load and merge custom rules if --rules-file is specified
		if rulesFileFlag != "" {
			customData, err := os.ReadFile(rulesFileFlag)
			if err != nil {
				return scanFinishedMsg{err: fmt.Errorf("failed to read custom rules file '%s': %w", rulesFileFlag, err)}
			}
			customRuleSet, err := detector.LoadRulesFromYAML(customData)
			if err != nil {
				return scanFinishedMsg{err: fmt.Errorf("failed to parse custom rules file '%s': %w", rulesFileFlag, err)}
			}
			ruleSet.Rules = append(ruleSet.Rules, customRuleSet.Rules...)
		}

		regexDet, err := detector.NewRegexDetector(ruleSet)
		if err != nil {
			return scanFinishedMsg{err: err}
		}

		detectors := []detector.Detector{regexDet}
		if entropyThreshold > 0 {
			detectors = append(detectors, detector.NewEntropyDetector(entropyThreshold))
		}

		ignoreMatcher := config.NewIgnoreMatcher(ignoreFileFlag)

		var all []detector.Finding

		// Filesystem scan
		fsScanner := scanner.NewFilesystemScanner(targetPath, detectors, ignoreMatcher)
		findings, err := fsScanner.Scan(context.Background())
		if err != nil {
			return scanFinishedMsg{err: err}
		}
		all = append(all, findings...)

		// Git history scan
		if includeGitHistory {
			gitScanner := scanner.NewGitScanner(targetPath, detectors, ignoreMatcher)
			if gFindings, gErr := gitScanner.Scan(context.Background()); gErr == nil {
				all = append(all, gFindings...)
			}
		}

		// Shell history scan
		if includeShell {
			shellScanner := scanner.NewShellHistoryScanner(detectors)
			if sFindings, sErr := shellScanner.Scan(context.Background()); sErr == nil {
				all = append(all, sFindings...)
			}
		}

		// Process environment scan
		if includeProcess {
			procScanner := scanner.NewProcessScanner(detectors)
			if pFindings, pErr := procScanner.Scan(context.Background()); pErr == nil {
				all = append(all, pFindings...)
			}
		}

		return scanFinishedMsg{findings: all}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch m.state {
		case stateHome:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "s", "enter":
				m.state = stateScanning
				m.status = "Scanning directory..."
				return m, runScanCmd(m.targetPath)
			}

		case stateScanning:
			if msg.String() == "q" || msg.String() == "ctrl+c" {
				return m, tea.Quit
			}

		case stateResults:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "b", "esc":
				m.state = stateHome
			case "j", "down":
				if m.cursor < len(m.findings)-1 {
					m.cursor++
				}
			case "k", "up":
				if m.cursor > 0 {
					m.cursor--
				}
			case "r":
				m.state = stateScanning
				m.status = "Rescanning..."
				return m, runScanCmd(m.targetPath)
			}
		}

	case scanFinishedMsg:
		if msg.err != nil {
			m.err = msg.err
			m.status = "Scan failed"
		} else {
			m.findings = msg.findings
			m.state = stateResults
			m.cursor = 0
		}
	}

	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	// Header Banner (LazyVim TokyoNight Palette)
	headerLogo := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#1a1b26")).
		Background(lipgloss.Color("#bb9af7")).
		Padding(0, 1).
		Render(" ⚡ LEAKSCAN TUI ⚡ ")

	headerText := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7aa2f7")).
		Bold(true).
		Render("  Secrets & Credential Scanner")

	b.WriteString(fmt.Sprintf("\n %s%s\n\n", headerLogo, headerText))

	switch m.state {
	case stateHome:
		b.WriteString(m.renderHomeView())
	case stateScanning:
		b.WriteString(m.renderScanningView())
	case stateResults:
		b.WriteString(m.renderResultsView())
	}

	// Status Line Footer
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m model) renderHomeView() string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7aa2f7")).
		Padding(1, 2).
		Width(65)

	title := lipgloss.NewStyle().Foreground(lipgloss.Color("#7dcfff")).Bold(true).Render("Welcome to LeakScan Interactive Mode")
	keyS := lipgloss.NewStyle().Foreground(lipgloss.Color("#bb9af7")).Bold(true).Render("[ s / Enter ]")
	keyQ := lipgloss.NewStyle().Foreground(lipgloss.Color("#f7768e")).Bold(true).Render("[ q ]")

	content := fmt.Sprintf(
		"%s\n\nTarget Path: %s\n\n  %s  Start Full Leak Scan\n  %s  Quit Application",
		title,
		lipgloss.NewStyle().Foreground(lipgloss.Color("#e0af68")).Render(m.targetPath),
		keyS,
		keyQ,
	)

	return boxStyle.Render(content) + "\n"
}

func (m model) renderScanningView() string {
	spinner := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0af68")).Bold(true).Render("⏳ Scanning files & environment...")
	return fmt.Sprintf("  %s\n  Please wait while patterns are evaluated...\n", spinner)
}

func (m model) renderResultsView() string {
	if len(m.findings) == 0 {
		cleanBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#9ece6a")).
			Padding(1, 2).
			Render("✔ NO LEAKS DETECTED! Your repository is completely clean.")
		return cleanBox + "\n"
	}

	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#7dcfff")).Bold(true).Render(fmt.Sprintf("Found %d Leaked Secret(s):\n\n", len(m.findings))))

	maxShow := 6
	for i := 0; i < len(m.findings) && i < maxShow; i++ {
		f := m.findings[i]
		isSel := (i == m.cursor)

		prefix := "  "
		if isSel {
			prefix = "> "
		}

		itemStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#a9b1d6"))
		if isSel {
			itemStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7aa2f7")).Bold(true)
		}

		sevBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("#1a1b26")).Padding(0, 1)
		switch strings.ToLower(f.Severity) {
		case "critical":
			sevBadge = sevBadge.Background(lipgloss.Color("#f7768e"))
		case "high":
			sevBadge = sevBadge.Background(lipgloss.Color("#e0af68"))
		default:
			sevBadge = sevBadge.Background(lipgloss.Color("#7dcfff"))
		}

		line := fmt.Sprintf("%s%s %s - %s (%s)", prefix, sevBadge.Render(strings.ToUpper(f.Severity)), f.Type, f.Location, f.Redacted)
		sb.WriteString(itemStyle.Render(line) + "\n")
	}

	if len(m.findings) > maxShow {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#565f89")).Render(fmt.Sprintf("\n  ... and %d more findings", len(m.findings)-maxShow)) + "\n")
	}

	return sb.String()
}

func (m model) renderFooter() string {
	keyHelp := lipgloss.NewStyle().Foreground(lipgloss.Color("#414868")).Render("󰌌  [s] Scan  [j/k] Navigate  [r] Rescan  [b] Back  [q] Quit")
	return keyHelp
}

var tuiCmd = &cobra.Command{
	Use:   "tui [path]",
	Short: "Launch interactive LazyVim styled TUI dashboard",
	Long:  `Opens an interactive terminal user interface with LazyVim TokyoNight aesthetics for leak scanning.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		p := tea.NewProgram(initialModel(targetPath))
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("failed to run TUI: %w", err)
		}
		return nil
	},
}

func init() {
	// Register all scan-relevant flags on the TUI command so users can pass
	// --include-git-history, --include-shell-history, etc. to 'leakscan tui'
	tuiCmd.Flags().BoolVar(&includeGitHistory, "include-git-history", false, "Scan full git commit history in repository")
	tuiCmd.Flags().BoolVar(&includeShell, "include-shell-history", false, "Scan local shell history (~/.bash_history, ~/.zsh_history)")
	tuiCmd.Flags().BoolVar(&includeProcess, "include-process-env", false, "Scan running process environment variables")
	tuiCmd.Flags().Float64Var(&entropyThreshold, "entropy-threshold", 3.8, "Shannon entropy threshold for high-entropy string detection (0 to disable)")
	tuiCmd.Flags().StringVar(&ignoreFileFlag, "ignore-file", ".leakscanner-ignore", "Path to ignore file")
	tuiCmd.Flags().StringVar(&rulesFileFlag, "rules-file", "", "Path to additional custom rules YAML file to merge with defaults")
	rootCmd.AddCommand(tuiCmd)
}
