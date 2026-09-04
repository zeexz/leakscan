package detector

import (
	"fmt"
	"regexp"
	"strings"
)

type compiledRule struct {
	rule      Rule
	re        *regexp.Regexp
	contextRe *regexp.Regexp // Optional: if non-nil, the line must also match this for the rule to fire
}

// RegexDetector scans content against compiled regex rules.
type RegexDetector struct {
	rules []compiledRule
}

// NewRegexDetector initializes a RegexDetector from a RuleSet.
func NewRegexDetector(ruleSet *RuleSet) (*RegexDetector, error) {
	compiled := make([]compiledRule, 0, len(ruleSet.Rules))
	for _, r := range ruleSet.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex for rule %s (%s): %w", r.ID, r.Pattern, err)
		}
		cr := compiledRule{
			rule: r,
			re:   re,
		}
		if r.ContextPattern != "" {
			ctxRe, err := regexp.Compile(r.ContextPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid context_pattern for rule %s (%s): %w", r.ID, r.ContextPattern, err)
			}
			cr.contextRe = ctxRe
		}
		compiled = append(compiled, cr)
	}
	return &RegexDetector{rules: compiled}, nil
}

// Detect checks text content against all compiled regex rules.
func (d *RegexDetector) Detect(content string, source SourceMeta) []Finding {
	var findings []Finding

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lineNum := source.LineNumber
		if lineNum <= 0 {
			lineNum = i + 1
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		prevLine := ""
		if i > 0 {
			prevLine = lines[i-1]
		}

		for _, cr := range d.rules {
			// Skip if inline comment directive ignores this rule or all rules
			if HasIgnoreDirective(line, prevLine, cr.rule.ID) {
				continue
			}

			// If context_pattern is set, the line must match it for the rule to fire
			if cr.contextRe != nil && !cr.contextRe.MatchString(line) {
				continue
			}

			matches := cr.re.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) == 0 {
					continue
				}
				// If submatch captures secret group specifically, use that; otherwise full match
				secretVal := m[0]
				if len(m) > 1 && m[len(m)-1] != "" {
					secretVal = m[len(m)-1]
				}

				redacted := RedactValue(secretVal)
				ZeroString(&secretVal) // Best-effort: overwrite raw secret in memory

				// Determine Source and Location strings based on SourceMeta
				srcStr, locStr := formatSourceAndLocation(source, lineNum)

				findings = append(findings, Finding{
					Source:      srcStr,
					Type:        cr.rule.Name,
					Location:    locStr,
					Severity:    cr.rule.Severity,
					Redacted:    redacted,
					Remediation: cr.rule.Remediation,
				})
			}
		}
	}

	return findings
}

func formatSourceAndLocation(meta SourceMeta, lineNum int) (string, string) {
	switch meta.Type {
	case "git":
		source := fmt.Sprintf("git:%s@%s", meta.RepoName, meta.CommitSHA)
		location := fmt.Sprintf("%s:%d (author: %s, date: %s)", meta.Path, lineNum, meta.Author, meta.CommitDate)
		return source, location
	case "shell_history":
		source := "shell_history"
		location := fmt.Sprintf("%s:%d", meta.Path, lineNum)
		return source, location
	case "process":
		source := fmt.Sprintf("process:%d", meta.PID)
		location := fmt.Sprintf("%s (PID %d)", meta.Process, meta.PID)
		return source, location
	default: // "file"
		source := fmt.Sprintf("file:%s", meta.Path)
		location := fmt.Sprintf("%s:%d", meta.Path, lineNum)
		return source, location
	}
}
