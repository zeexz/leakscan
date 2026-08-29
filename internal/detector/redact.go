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

// ZeroString is a best-effort mitigation that sets the string pointer to empty.
// In Go, strings may share backing memory with literals in read-only segments,
// so we cannot safely overwrite the underlying bytes via unsafe. Instead we:
//   1. Convert to a mutable byte slice (copies to writable heap memory)
//   2. Zero every byte in that writable copy
//   3. Set the original string to empty
//
// This limits the window during which the secret exists in the caller's variable
// but does NOT guarantee the original backing memory is zeroed. Go's garbage
// collector may also retain copies. This is "best effort, not formally verified."
func ZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// Create a writable copy on the heap and zero it
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}
