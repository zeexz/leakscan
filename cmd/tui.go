package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"leakscan/internal/detector"
	"leakscan/internal/engine"
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

// spinnerTickMsg drives the scanning animation.
type spinnerTickMsg struct{}

type model struct {
	state        state
	targetPath   string
	findings     []detector.Finding
	cursor       int
	scrollOffset int // viewport scroll offset
	status       string
	err          error
	width        int
	height       int
	spinnerFrame int
}

// Spinner animation frames
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

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
		cfg := buildConfig([]string{targetPath})
		result, err := engine.Run(context.Background(), cfg)
		if err != nil {
			return scanFinishedMsg{err: err}
		}
		return scanFinishedMsg{findings: result.Findings}
	}
}

func spinnerTick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(_ time.Time) tea.Msg {
		return spinnerTickMsg{}
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinnerTickMsg:
		if m.state == stateScanning {
			m.spinnerFrame = (m.spinnerFrame + 1) % len(spinnerFrames)
			return m, spinnerTick()
		}

	case tea.KeyMsg:
		switch m.state {
		case stateHome:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "s", "enter":
				m.state = stateScanning
				m.status = "Scanning directory..."
				return m, tea.Batch(runScanCmd(m.targetPath), spinnerTick())
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
					// Auto-scroll to keep cursor visible
					maxVisible := m.visibleCount()
					if m.cursor >= m.scrollOffset+maxVisible {
						m.scrollOffset = m.cursor - maxVisible + 1
					}
				}
			case "k", "up":
				if m.cursor > 0 {
					m.cursor--
					// Auto-scroll to keep cursor visible
					if m.cursor < m.scrollOffset {
						m.scrollOffset = m.cursor
					}
				}
			case "r":
				m.state = stateScanning
				m.status = "Rescanning..."
				return m, tea.Batch(runScanCmd(m.targetPath), spinnerTick())
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
			m.scrollOffset = 0
		}
	}

	return m, nil
}

// visibleCount returns how many findings can be shown based on terminal height.
func (m model) visibleCount() int {
	maxShow := m.height - 10 // Reserve space for header, footer, margins
	if maxShow < 3 {
		maxShow = 3
	}
	if maxShow > len(m.findings) {
		maxShow = len(m.findings)
	}
	return maxShow
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
	frame := spinnerFrames[m.spinnerFrame%len(spinnerFrames)]
	spinner := lipgloss.NewStyle().Foreground(lipgloss.Color("#e0af68")).Bold(true).Render(fmt.Sprintf("%s Scanning files & environment...", frame))
	detail := lipgloss.NewStyle().Foreground(lipgloss.Color("#565f89")).Render("  Running regex patterns + entropy analysis in parallel...")
	return fmt.Sprintf("  %s\n%s\n", spinner, detail)
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

	// Summary header
	summaryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#7dcfff")).Bold(true)
	sb.WriteString(summaryStyle.Render(fmt.Sprintf("Found %d Leaked Secret(s):", len(m.findings))))
	sb.WriteString("\n\n")

	// Viewport-based scrolling
	maxVisible := m.visibleCount()
	endIdx := m.scrollOffset + maxVisible
	if endIdx > len(m.findings) {
		endIdx = len(m.findings)
	}

	for i := m.scrollOffset; i < endIdx; i++ {
		f := m.findings[i]
		isSel := (i == m.cursor)

		prefix := "  "
		if isSel {
			prefix = "▸ "
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

	// Scroll indicator
	if len(m.findings) > maxVisible {
		scrollInfo := lipgloss.NewStyle().Foreground(lipgloss.Color("#565f89")).Render(
			fmt.Sprintf("\n  [%d/%d] ↑↓ to scroll", m.cursor+1, len(m.findings)))
		sb.WriteString(scrollInfo + "\n")
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
	tuiCmd.Flags().Int64Var(&maxFileSizeFlag, "max-file-size", 0, "Skip files larger than this size in bytes (0 = no limit)")
	rootCmd.AddCommand(tuiCmd)
}
