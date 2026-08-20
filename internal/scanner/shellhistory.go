package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"leakscan/internal/detector"
)

// ShellHistoryScanner reads local shell history files (~/.bash_history, ~/.zsh_history, $HISTFILE).
type ShellHistoryScanner struct {
	detectors []detector.Detector
}

// NewShellHistoryScanner creates a ShellHistoryScanner instance.
func NewShellHistoryScanner(detectors []detector.Detector) *ShellHistoryScanner {
	return &ShellHistoryScanner{detectors: detectors}
}

func (s *ShellHistoryScanner) Name() string {
	return "shell_history"
}

func (s *ShellHistoryScanner) Scan(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	historyFiles := getShellHistoryPaths()

	for _, histPath := range historyFiles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if _, err := os.Stat(histPath); os.IsNotExist(err) {
			continue
		}

		file, err := os.Open(histPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// zsh history files may start lines with timestamp formatted as ": 1600000000:0;command"
			cleanLine := cleanZshHistoryLine(line)
			if strings.TrimSpace(cleanLine) == "" {
				continue
			}

			meta := detector.SourceMeta{
				Type:       "shell_history",
				Path:       histPath,
				LineNumber: lineNum,
			}

			for _, d := range s.detectors {
				found := d.Detect(cleanLine, meta)
				for _, item := range found {
					item.Remediation += " Clear secret from shell history file immediately (e.g. edit history file or run 'history -c')."
					findings = append(findings, item)
				}
			}
		}
		file.Close()
	}

	return findings, nil
}

func getShellHistoryPaths() []string {
	var paths []string

	if histFile := os.Getenv("HISTFILE"); histFile != "" {
		paths = append(paths, histFile)
	}

	homeDir, err := os.UserHomeDir()
	if err == nil && homeDir != "" {
		paths = append(paths,
			filepath.Join(homeDir, ".bash_history"),
			filepath.Join(homeDir, ".zsh_history"),
			filepath.Join(homeDir, ".history"),
		)
	}

	return paths
}

func cleanZshHistoryLine(line string) string {
	// zsh extended history format: ": 1612345678:0;actual command"
	if strings.HasPrefix(line, ": ") {
		if idx := strings.Index(line, ";"); idx != -1 {
			return line[idx+1:]
		}
	}
	return line
}
