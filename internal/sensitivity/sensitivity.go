// Package sensitivity classifies the resources NIA's gateway and risk
// engine reason about, a tool argument, a data object named in a
// policy.Grant, into one of five levels: public, internal, confidential,
// sensitive, critical. This is deliberately rule-based rather than
// inferred: an operator declares that "customer.ssn" is sensitive, the
// classifier looks it up, nothing here guesses. That's what makes a
// classification reproducible and explainable, the same requirement
// docs/ARCHITECTURE.md holds internal/risk to, an incident review needs
// to be able to answer "why was this flagged as sensitive" with a rule,
// not a black box.
//
// This package has no opinion on what counts as a resource name or how
// cmd/gateway extracts one from a tool call's arguments, that's the
// gateway's own concern, layered on top once it starts inspecting
// arguments rather than only the tool name. See internal/policy's
// GrantForData for the authorization side of the same idea: a data
// object gets a level here and a grant there, the two are meant to be
// read together, not duplicated into two separate concepts.
package sensitivity

import "fmt"

// Level orders from least to most sensitive. The zero value is Public
// on purpose: an object nothing declared a rule for is not sensitive,
// which is the same "an operator has to opt in, not opt out" posture
// every other unconfigured feature in this codebase takes, not a
// judgment that unclassified data is actually safe.
type Level int

const (
	Public Level = iota
	Internal
	Confidential
	Sensitive
	Critical
)

func (l Level) String() string {
	switch l {
	case Public:
		return "public"
	case Internal:
		return "internal"
	case Confidential:
		return "confidential"
	case Sensitive:
		return "sensitive"
	case Critical:
		return "critical"
	default:
		return fmt.Sprintf("sensitivity.Level(%d)", int(l))
	}
}

// ParseLevel is the inverse of String, case-sensitive, lowercase, the
// same shape a config file or an HTTP request body would carry it in.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "public":
		return Public, nil
	case "internal":
		return Internal, nil
	case "confidential":
		return Confidential, nil
	case "sensitive":
		return Sensitive, nil
	case "critical":
		return Critical, nil
	default:
		return 0, fmt.Errorf("sensitivity: unknown level %q, want one of public, internal, confidential, sensitive, critical", s)
	}
}

// Rule ties one resource pattern to a level. Pattern names the object
// the same way internal/policy.GrantForData does, "customer.ssn",
// "credential.material", a rule and a grant are meant to name the same
// thing the same way. Pattern supports one trailing "*" as a prefix
// wildcard, "credential.*" matches any object with that prefix, nothing
// fancier than that on purpose, so what a rule matches is always
// obvious from reading it, not from tracing a regex engine.
type Rule struct {
	Pattern string
	Level   Level
}

// Classifier maps a resource object name to the level an operator
// declared for it.
type Classifier interface {
	Classify(object string) Level
}

// RuleClassifier is the reference Classifier: an ordered rule list,
// first match wins. Rules are copied in at construction and never
// mutated afterward, so a RuleClassifier is safe for concurrent use
// without a lock, there's nothing to race over.
type RuleClassifier struct {
	rules []Rule
}

// NewRuleClassifier builds a classifier from rules, evaluated in the
// order given, so put more specific patterns ahead of broader ones,
// "customer.ssn" ahead of "customer.*", the same responsibility any
// ordered rule list puts on its caller.
func NewRuleClassifier(rules []Rule) *RuleClassifier {
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	return &RuleClassifier{rules: cp}
}

// Classify returns the level of the first matching rule, or Public if
// nothing matches.
func (c *RuleClassifier) Classify(object string) Level {
	for _, r := range c.rules {
		if patternMatches(r.Pattern, object) {
			return r.Level
		}
	}
	return Public
}

func patternMatches(pattern, object string) bool {
	if pattern == object {
		return true
	}
	if n := len(pattern); n > 0 && pattern[n-1] == '*' {
		prefix := pattern[:n-1]
		return len(object) >= len(prefix) && object[:len(prefix)] == prefix
	}
	return false
}

var _ Classifier = (*RuleClassifier)(nil)
