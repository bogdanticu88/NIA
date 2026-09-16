package main

import "testing"

func TestFieldResourcePolicy_NoMatchingRuleForTool_ReturnsNothing(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	got := p.Resources("customer.export", map[string]any{"table": "customers", "columns": []any{"ssn"}})
	if len(got) != 0 {
		t.Fatalf("got %v, want no resources for a tool with no matching rule", got)
	}
}

func TestFieldResourcePolicy_QualifiedByAnotherField(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	got := p.Resources("database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name", "email", "ssn"},
	})
	want := []string{"customers.name", "customers.email", "customers.ssn"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFieldResourcePolicy_NoQualifierFieldUsesToolItself(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "invoice.export", FieldsField: "fields"},
	})
	got := p.Resources("invoice.export", map[string]any{"fields": []any{"total", "notes"}})
	want := []string{"invoice.export.total", "invoice.export.notes"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFieldResourcePolicy_FieldsFieldAsSingleString(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	got := p.Resources("database.query", map[string]any{"table": "customers", "columns": "ssn"})
	want := []string{"customers.ssn"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFieldResourcePolicy_NonStringElementsAreSkipped(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	got := p.Resources("database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name", 42, "ssn"},
	})
	want := []string{"customers.name", "customers.ssn"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v, a non-string element should be skipped, not fail the whole call", got, want)
	}
}

func TestFieldResourcePolicy_MissingFieldsFieldReturnsNothing(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	got := p.Resources("database.query", map[string]any{"table": "customers"})
	if len(got) != 0 {
		t.Fatalf("got %v, want no resources when the configured fields_field is absent from arguments", got)
	}
}

func TestFieldResourcePolicy_MultipleRulesForSameTool_AllContribute(t *testing.T) {
	p := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
		{Tool: "database.query", QualifierField: "joinTable", FieldsField: "joinColumns"},
	})
	got := p.Resources("database.query", map[string]any{
		"table":       "customers",
		"columns":     []any{"ssn"},
		"joinTable":   "orders",
		"joinColumns": []any{"total"},
	})
	want := []string{"customers.ssn", "orders.total"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFieldResourcePolicy_MutatingInputAfterConstructionDoesNotAffectIt(t *testing.T) {
	rules := []ResourceRule{{Tool: "database.query", FieldsField: "columns"}}
	p := NewFieldResourcePolicy(rules)
	rules[0].Tool = "something.else"

	got := p.Resources("database.query", map[string]any{"columns": []any{"ssn"}})
	want := []string{"database.query.ssn"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v, NewFieldResourcePolicy must copy its input", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
