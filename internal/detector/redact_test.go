package detector

import (
	"testing"
)

func TestRedactValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Short secret <= 4 chars",
			input:    "1234",
			expected: "[REDACTED]",
		},
		{
			name:     "Medium secret 5-8 chars",
			input:    "secret1",
			expected: "s*****1",
		},
		{
			name:     "AWS Access Key ID 20 chars",
			input:    "AKIA" + "IOSFODNN7EXAMPLE",
			expected: "AKIA************MPLE",
		},
		{
			name:     "GitHub token 40 chars",
			input:    "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
			expected: "ghp_************************wxyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactValue(tt.input)
			if got == tt.input {
				t.Fatalf("RedactValue failed: returned unredacted raw secret '%s'", got)
			}
			if got != tt.expected {
				t.Errorf("RedactValue(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}
