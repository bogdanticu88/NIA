package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// envResourceRulesPath names a JSON file of ResourceRules. Unset is the
// same "off means off" posture every other FromEnv constructor in this
// codebase takes: no rules configured means Resources(...) is never
// even asked, argument inspection doesn't run at all, not a silent
// default that inspects nothing found.
const envResourceRulesPath = "NIA_GATEWAY_RESOURCE_RULES_PATH"

type resourceRuleFile struct {
	Tool           string `json:"tool"`
	QualifierField string `json:"qualifier_field"`
	FieldsField    string `json:"fields_field"`
}

// resourcePolicyFromEnv builds a FieldResourcePolicy from the rules
// file NIA_GATEWAY_RESOURCE_RULES_PATH points at. Unset returns (nil,
// nil), meaning argument inspection is not configured, handleToolCall
// skips it entirely, the same shape tools.FromEnvReader and
// monitoring.ThresholdsFromEnv already use for "not configured."
func resourcePolicyFromEnv() (ArgumentResourcePolicy, error) {
	path := os.Getenv(envResourceRulesPath)
	if path == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nia-gateway: reading %s (%s): %w", envResourceRulesPath, path, err)
	}
	var files []resourceRuleFile
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, fmt.Errorf("nia-gateway: parsing %s: %w", path, err)
	}

	rules := make([]ResourceRule, 0, len(files))
	for _, f := range files {
		if f.Tool == "" {
			return nil, fmt.Errorf("nia-gateway: %s has a rule with no tool", path)
		}
		if f.FieldsField == "" {
			return nil, fmt.Errorf("nia-gateway: %s has a rule for tool %q with no fields_field", path, f.Tool)
		}
		rules = append(rules, ResourceRule{
			Tool:           f.Tool,
			QualifierField: f.QualifierField,
			FieldsField:    f.FieldsField,
		})
	}
	return NewFieldResourcePolicy(rules), nil
}
