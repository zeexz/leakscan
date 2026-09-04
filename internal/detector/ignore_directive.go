package detector

import (
	"regexp"
	"strings"
)

// directiveRegex matches patterns like:
// leakscan:ignore
// leakscan:ignore[rule-id]
// with optional reason="..." or notes afterwards.
var directiveRegex = regexp.MustCompile(`(?i)leakscan:ignore(?:\[([a-zA-Z0-9_\-]+)\])?`)

// HasIgnoreDirective checks if a given line (or its immediately preceding line)
// contains an inline ignore directive that suppresses findings for ruleID.
//
// If ruleID is empty, it matches any general ignore directive.
// If the directive specifies a specific rule ID (e.g. leakscan:ignore[aws-access-key-id]),
// it suppresses if ruleID matches.
func HasIgnoreDirective(line string, prevLine string, ruleID string) bool {
	if checkLineForDirective(line, ruleID) {
		return true
	}
	if prevLine != "" && isCommentOnlyLine(prevLine) && checkLineForDirective(prevLine, ruleID) {
		return true
	}
	return false
}

// checkLineForDirective inspects whether text contains leakscan:ignore matching ruleID.
func checkLineForDirective(text string, ruleID string) bool {
	matches := directiveRegex.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return false
	}

	for _, m := range matches {
		targetRule := strings.TrimSpace(m[1])
		// If no specific rule ID specified in [rule-id], it ignores ALL rules on this line
		if targetRule == "" {
			return true
		}
		// If ruleID matches specified target rule ID (case-insensitive)
		if strings.EqualFold(targetRule, ruleID) {
			return true
		}
	}

	return false
}

// isCommentOnlyLine returns true if the line consists solely of a comment (//, #, /*, <!--, ;, --)
func isCommentOnlyLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--") ||
		strings.HasPrefix(trimmed, ";") ||
		strings.HasPrefix(trimmed, "--")
}
