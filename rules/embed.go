package rules

import _ "embed"

// DefaultPatternsYAML embeds default-patterns.yaml into binary.
//
//go:embed default-patterns.yaml
var DefaultPatternsYAML []byte
