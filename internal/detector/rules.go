package detector

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Rule defines a single regex detection rule loaded from YAML config.
type Rule struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	Description    string `yaml:"description"`
	Pattern        string `yaml:"pattern"`
	ContextPattern string `yaml:"context_pattern"` // Optional: line must also match this regex for the rule to fire
	Severity       string `yaml:"severity"`
	Remediation    string `yaml:"remediation"`
}

// RuleSet contains a collection of rules.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// LoadRulesFromYAML parses YAML byte data into a RuleSet and validates each rule.
func LoadRulesFromYAML(data []byte) (*RuleSet, error) {
	var ruleSet RuleSet
	err := yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Validate rules
	seenIDs := make(map[string]bool)
	for i, r := range ruleSet.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule[%d]: missing required 'id' field", i)
		}
		if seenIDs[r.ID] {
			return nil, fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seenIDs[r.ID] = true

		if r.Pattern == "" {
			return nil, fmt.Errorf("rule %q: missing required 'pattern' field", r.ID)
		}

		switch r.Severity {
		case "critical", "high", "medium":
			// valid
		case "":
			// default empty severity to "medium"
			ruleSet.Rules[i].Severity = "medium"
		default:
			return nil, fmt.Errorf("rule %q: invalid severity %q (must be critical, high, or medium)", r.ID, r.Severity)
		}
	}

	return &ruleSet, nil
}
