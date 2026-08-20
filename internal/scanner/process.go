package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"leakscan/internal/detector"
)

// ProcessScanner inspects running process environment variables for exposed secrets.
type ProcessScanner struct {
	detectors []detector.Detector
}

// NewProcessScanner creates a ProcessScanner instance.
func NewProcessScanner(detectors []detector.Detector) *ProcessScanner {
	return &ProcessScanner{detectors: detectors}
}

func (s *ProcessScanner) Name() string {
	return "process_env"
}

func (s *ProcessScanner) Scan(ctx context.Context) ([]detector.Finding, error) {
	switch runtime.GOOS {
	case "linux":
		return s.scanLinuxProc(ctx)
	case "windows":
		return s.scanWindowsProc(ctx)
	default:
		return s.scanGenericProc(ctx)
	}
}

func (s *ProcessScanner) scanLinuxProc(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return findings, nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		envPath := filepath.Join("/proc", entry.Name(), "environ")
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			continue // Skip unreadable process env
		}

		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		cmdlineBytes, _ := os.ReadFile(cmdlinePath)
		procName := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		if procName == "" {
			procName = fmt.Sprintf("PID %d", pid)
		}

		// /proc/*/environ uses null bytes as delimiter
		envVars := strings.Split(string(envBytes), "\x00")
		for _, envVar := range envVars {
			if strings.TrimSpace(envVar) == "" {
				continue
			}

			meta := detector.SourceMeta{
				Type:    "process",
				PID:     pid,
				Process: procName,
			}

			for _, d := range s.detectors {
				found := d.Detect(envVar, meta)
				for _, item := range found {
					item.Remediation += " WARNING: Exposed process environment variables can be inspected by other local users on shared multi-user systems. Store secrets in secret managers or pass securely."
					findings = append(findings, item)
				}
			}
		}
	}

	return findings, nil
}

func (s *ProcessScanner) scanWindowsProc(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding

	// Query PowerShell for current user processes and environment
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "Get-ChildItem Env: | Select-Object Name, Value | ConvertTo-Json")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return findings, nil
	}

	meta := detector.SourceMeta{
		Type:    "process",
		PID:     os.Getpid(),
		Process: "Current User Environment",
	}

	for _, d := range s.detectors {
		found := d.Detect(out.String(), meta)
		for _, item := range found {
			item.Remediation += " Process environment contains plain-text secret. Unset sensitive environment variables after process execution."
			findings = append(findings, item)
		}
	}

	return findings, nil
}

func (s *ProcessScanner) scanGenericProc(ctx context.Context) ([]detector.Finding, error) {
	var findings []detector.Finding
	// Scan current process environment variables as fallback
	environ := os.Environ()
	meta := detector.SourceMeta{
		Type:    "process",
		PID:     os.Getpid(),
		Process: "Process Environment",
	}

	for _, envVar := range environ {
		for _, d := range s.detectors {
			found := d.Detect(envVar, meta)
			for _, item := range found {
				findings = append(findings, item)
			}
		}
	}

	return findings, nil
}
