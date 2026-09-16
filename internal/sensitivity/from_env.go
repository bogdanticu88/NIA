package sensitivity

import (
	"encoding/json"
	"fmt"
	"os"
)

// envRulesPath names a JSON file of classification rules. Unset is the
// same "off means off" posture internal/monitoring.ThresholdsFromEnv
// and internal/registry/tools.FromEnvReader already take: nothing here
// should silently start treating resources as sensitive just because
// the package exists, an operator has to declare rules for that.
const envRulesPath = "NIA_SENSITIVITY_RULES_PATH"

// ruleFile is one entry in the JSON file NIA_SENSITIVITY_RULES_PATH
// points at: a flat array of {"pattern": "...", "level": "..."}, level
// spelled the same way Level.String() renders it.
type ruleFile struct {
	Pattern string `json:"pattern"`
	Level   string `json:"level"`
}

// FromEnvClassifier builds a RuleClassifier from the rules file named
// by NIA_SENSITIVITY_RULES_PATH. Unset returns a classifier with no
// rules, every object classifies as Public, not an error, same as
// every other FromEnv constructor in this codebase treats "not
// configured" as a valid, safe starting state rather than a failure.
func FromEnvClassifier() (Classifier, error) {
	path := os.Getenv(envRulesPath)
	if path == "" {
		return NewRuleClassifier(nil), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sensitivity: reading %s (%s): %w", envRulesPath, path, err)
	}
	var files []ruleFile
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, fmt.Errorf("sensitivity: parsing %s: %w", path, err)
	}

	rules := make([]Rule, 0, len(files))
	for _, f := range files {
		if f.Pattern == "" {
			return nil, fmt.Errorf("sensitivity: %s has a rule with an empty pattern", path)
		}
		level, err := ParseLevel(f.Level)
		if err != nil {
			return nil, fmt.Errorf("sensitivity: rule for %q in %s: %w", f.Pattern, path, err)
		}
		rules = append(rules, Rule{Pattern: f.Pattern, Level: level})
	}
	return NewRuleClassifier(rules), nil
}
