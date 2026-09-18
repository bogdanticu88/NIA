package main

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// This file is the response-side counterpart to resources.go. That one
// answers "what is this call asking for" from the request's arguments;
// this one answers "what did it actually come back with" from the
// downstream's response body.
//
// The gap it closes is stated directly in docs/THREAT_MODEL.md's threat
// 6: before it, a downstream tool returning a plausible-looking 200 full
// of data the agent was never authorized to see raised none of the
// gateway's checks. The request said database.query on a table the agent
// is granted, the response carried an ssn column nobody granted, and the
// only thing the gateway noticed was that the call succeeded.
//
// The deliberate limit, and it is the same one internal/sensitivity
// makes for itself: this is not a content scanner, it does not try to
// recognize a social security number by shape, and it will not notice
// sensitive data under a field name nobody declared. It matches field
// names against the operator's own declared rules, which means it is
// explainable ("this fired because you declared customers.ssn
// sensitive") and it is exactly as complete as those rules are.
// Explainable over inferred, the same trade the sensitivity package's
// own doc comment makes.

// maxResponseInspectionDepth bounds how deep the walk goes into a
// response. Arbitrarily nested JSON is attacker-influenced input on the
// hot path, and a recursive walk with no bound is a stack exhaustion
// waiting for a downstream that returns ten thousand nested objects.
// Eight is deeper than any real tool response this has to understand.
const maxResponseInspectionDepth = 8

// maxResponseFieldsInspected bounds how many distinct field paths are
// collected from one response, for the same reason: a response with a
// hundred thousand distinct keys should cost a bounded amount of work,
// not an unbounded one.
const maxResponseFieldsInspected = 512

// sensitiveResponseFields walks a JSON response body and returns the
// field paths that classify at Sensitive or above, sorted, deduplicated.
//
// Paths are dotted and array indices are dropped, so a list of customer
// records reports "customers.ssn" once rather than once per row. That
// matters for two reasons: it is the same shape the resource rules and
// data grants are written in, so a path can be handed straight to
// policy.GrantForData, and an audit line naming one field is readable
// where one naming four hundred is not.
//
// A non-JSON body returns nothing. This walks structure, it does not
// grep, so an opaque or binary response is simply outside what this can
// say anything about, which is worth knowing rather than papering over.
func sensitiveResponseFields(body []byte, classifier sensitivity.Classifier) []string {
	if classifier == nil || len(body) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}

	found := map[string]sensitivity.Level{}
	walkJSONFields(decoded, "", 0, found, classifier)
	if len(found) == 0 {
		return nil
	}

	out := make([]string, 0, len(found))
	for path := range found {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func walkJSONFields(v any, prefix string, depth int, found map[string]sensitivity.Level, classifier sensitivity.Classifier) {
	if depth > maxResponseInspectionDepth || len(found) >= maxResponseFieldsInspected {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for key, child := range t {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			// Both the full path and the bare field name are classified.
			// An operator writing a rule for "customers.ssn" and one
			// writing "ssn" are both making a reasonable declaration, and
			// requiring them to guess the downstream's exact nesting
			// would make the feature useless in practice.
			for _, candidate := range []string{path, key} {
				if lvl := classifier.Classify(candidate); lvl >= sensitivity.Sensitive {
					if existing, ok := found[path]; !ok || lvl > existing {
						found[path] = lvl
					}
					break
				}
			}
			walkJSONFields(child, path, depth+1, found, classifier)
		}
	case []any:
		// Array indices are deliberately not part of the path, see the
		// doc comment: one row and ten thousand rows report the same
		// field once.
		for _, child := range t {
			walkJSONFields(child, prefix, depth+1, found, classifier)
		}
	}
}

// formatFieldList renders field paths for an audit detail string,
// truncated so one pathological response cannot write a megabyte into
// the audit trail. The count is always reported, so a reader can tell a
// truncated list from a complete one.
func formatFieldList(fields []string) string {
	const maxListed = 10
	if len(fields) <= maxListed {
		return strings.Join(fields, ",")
	}
	return strings.Join(fields[:maxListed], ",") + ",... (" + itoa(len(fields)-maxListed) + " more)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
