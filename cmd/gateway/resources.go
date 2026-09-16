package main

// ArgumentResourcePolicy extracts the resource object names a tool
// call's arguments reference, so handleToolCall can check sensitivity
// and a data-scoped grant for those specific resources, not just the
// tool itself. This is the Agent+Tool+Action+Resource+Context decision
// the package doc comment above describes, layered on top of the
// existing Agent+Tool check rather than replacing it.
//
// Resource names returned here are meant to line up with
// policy.GrantForData's Object and a sensitivity.Rule's Pattern, the
// three are three views of the same name, see internal/sensitivity's
// own package doc for why.
type ArgumentResourcePolicy interface {
	// Resources returns the resource object names this call touches.
	// A nil or empty result means the policy found nothing beyond the
	// tool-level grant already checked, not an error.
	Resources(tool string, arguments map[string]any) []string
}

// ResourceRule is one entry in a FieldResourcePolicy: for a given tool,
// build one resource name per value found at FieldsField, qualified by
// the value at QualifierField. A database.query call with
// {"table": "customers", "columns": ["name", "ssn"]} and the rule
// {Tool: "database.query", QualifierField: "table", FieldsField:
// "columns"} produces "customers.name" and "customers.ssn". An empty
// QualifierField uses Tool itself as the qualifier instead, "<tool>.<field>".
//
// This is deliberately flat, one level of lookup into the arguments
// map, no nested paths, no templating language: what a rule extracts
// should be obvious from reading it, the same reasoning
// sensitivity.Rule's single trailing "*" wildcard uses. A tool whose
// arguments need more than this to name its resources needs a
// purpose-built ArgumentResourcePolicy, not a more powerful version of
// this one.
type ResourceRule struct {
	Tool           string
	QualifierField string
	FieldsField    string
}

// FieldResourcePolicy is the reference ArgumentResourcePolicy: explicit,
// operator-declared rules, no inference into an argument's shape or
// meaning beyond "this field names a resource qualifier, that field
// names the parts of it being touched." Rules are copied in at
// construction and never mutated, safe for concurrent use without a
// lock.
type FieldResourcePolicy struct {
	rules []ResourceRule
}

// NewFieldResourcePolicy builds a policy from rules. More than one rule
// may match the same tool, e.g. one FieldsField for columns and another
// for a joined table, all matching rules contribute resources.
func NewFieldResourcePolicy(rules []ResourceRule) *FieldResourcePolicy {
	cp := make([]ResourceRule, len(rules))
	copy(cp, rules)
	return &FieldResourcePolicy{rules: cp}
}

func (p *FieldResourcePolicy) Resources(tool string, arguments map[string]any) []string {
	var out []string
	for _, r := range p.rules {
		if r.Tool != tool {
			continue
		}
		qualifier := r.Tool
		if r.QualifierField != "" {
			if v, ok := stringField(arguments, r.QualifierField); ok && v != "" {
				qualifier = v
			}
		}
		for _, field := range stringSliceField(arguments, r.FieldsField) {
			if field == "" {
				continue
			}
			out = append(out, qualifier+"."+field)
		}
	}
	return out
}

func stringField(args map[string]any, field string) (string, bool) {
	v, ok := args[field]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// stringSliceField reads field as either a single string (returned as
// a one-element slice) or a JSON array of strings, encoding/json
// decodes an array into a map[string]any as []any, so that's the shape
// actually seen here, not []string. A non-string element is skipped
// rather than failing the whole call, one malformed entry shouldn't
// blind the rest of the inspection.
func stringSliceField(args map[string]any, field string) []string {
	v, ok := args[field]
	if !ok {
		return nil
	}
	switch vv := v.(type) {
	case string:
		return []string{vv}
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

var _ ArgumentResourcePolicy = (*FieldResourcePolicy)(nil)
