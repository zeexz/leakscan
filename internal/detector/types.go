package detector

import "context"

// Finding represents a single detected secret leak.
type Finding struct {
	Source      string `json:"source"`      // e.g. "shell_history", "git:repo-name@sha", "process:1234", "file:/path"
	Type        string `json:"type"`        // e.g. "AWS Access Key", "High entropy string"
	Location    string `json:"location"`    // file path + line number, or process name/PID
	Severity    string `json:"severity"`    // "critical" | "high" | "medium"
	Redacted    string `json:"redacted"`    // e.g. "AKIA****************ABCD" - never full secret
	Remediation string `json:"remediation"` // actionable next step
}

// SourceMeta carries contextual metadata about where content originated.
type SourceMeta struct {
	Type       string // "file", "git", "shell_history", "process"
	Path       string // File path or repository path
	LineNumber int    // Line number in file or history
	RepoName   string // Git repository name
	CommitSHA  string // Git commit hash
	CommitDate string // Git commit date/time
	Author     string // Git commit author
	PID        int    // Process ID
	Process    string // Process name / command line
}

// Detector evaluates content strings and returns findings.
type Detector interface {
	Detect(content string, source SourceMeta) []Finding
}

// Scanner defines the interface for all scanning sources.
type Scanner interface {
	Name() string
	Scan(ctx context.Context) ([]Finding, error)
}
