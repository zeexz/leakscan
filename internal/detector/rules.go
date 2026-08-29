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

// LoadRulesFromYAML parses YAML byte data into a RuleSet.
func LoadRulesFromYAML(data []byte) (*RuleSet, error) {
	var ruleSet RuleSet
	err := yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}
	return &ruleSet, nil
}
