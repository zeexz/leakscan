package detector

import (
	"strings"
)

// RedactValue masks a sensitive secret string so it never reveals the full secret.
// For strings > 8 characters: shows first 4 chars, stars, last 4 chars.
// For strings between 5 and 8 characters: shows first 1 char, stars, last 1 char.
// For strings <= 4 characters: returns "[REDACTED]".
func RedactValue(secret string) string {
	secret = strings.TrimSpace(secret)
	n := len(secret)
	if n <= 4 {
		return "[REDACTED]"
	}
	if n <= 8 {
		prefix := secret[:1]
		suffix := secret[n-1:]
		stars := strings.Repeat("*", n-2)
		return prefix + stars + suffix
	}

	prefix := secret[:4]
	suffix := secret[n-4:]
	starLen := n - 8
	if starLen < 8 {
		starLen = 8
	} else if starLen > 24 {
		starLen = 24
	}
	stars := strings.Repeat("*", starLen)
	return prefix + stars + suffix
}
