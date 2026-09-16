package sensitivity

import "testing"

func TestLevel_StringAndParse_RoundTrip(t *testing.T) {
	levels := []Level{Public, Internal, Confidential, Sensitive, Critical}
	for _, want := range levels {
		s := want.String()
		got, err := ParseLevel(s)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", s, err)
		}
		if got != want {
			t.Fatalf("ParseLevel(String(%v)) = %v, want %v", want, got, want)
		}
	}
}

func TestParseLevel_UnknownIsAnError(t *testing.T) {
	if _, err := ParseLevel("top-secret"); err == nil {
		t.Fatal("expected an error for an unknown level, got nil")
	}
}

func TestRuleClassifier_NoRulesIsAlwaysPublic(t *testing.T) {
	c := NewRuleClassifier(nil)
	if got := c.Classify("customer.ssn"); got != Public {
		t.Fatalf("Classify with no rules = %v, want Public", got)
	}
}

func TestRuleClassifier_ExactMatch(t *testing.T) {
	c := NewRuleClassifier([]Rule{
		{Pattern: "customer.ssn", Level: Critical},
	})
	if got := c.Classify("customer.ssn"); got != Critical {
		t.Fatalf("Classify(customer.ssn) = %v, want Critical", got)
	}
	if got := c.Classify("customer.email"); got != Public {
		t.Fatalf("Classify(customer.email) = %v, want Public, no rule matches it", got)
	}
}

func TestRuleClassifier_PrefixWildcard(t *testing.T) {
	c := NewRuleClassifier([]Rule{
		{Pattern: "credential.*", Level: Critical},
	})
	if got := c.Classify("credential.material"); got != Critical {
		t.Fatalf("Classify(credential.material) = %v, want Critical", got)
	}
	if got := c.Classify("credentials.material"); got != Public {
		t.Fatalf("Classify(credentials.material) = %v, want Public, credential.* should not match a different prefix", got)
	}
}

func TestRuleClassifier_FirstMatchWins(t *testing.T) {
	c := NewRuleClassifier([]Rule{
		{Pattern: "customer.ssn", Level: Critical},
		{Pattern: "customer.*", Level: Confidential},
	})
	if got := c.Classify("customer.ssn"); got != Critical {
		t.Fatalf("Classify(customer.ssn) = %v, want Critical from the more specific rule listed first", got)
	}
	if got := c.Classify("customer.email"); got != Confidential {
		t.Fatalf("Classify(customer.email) = %v, want Confidential from the wildcard rule", got)
	}
}

func TestRuleClassifier_MutatingInputAfterConstructionDoesNotAffectIt(t *testing.T) {
	rules := []Rule{{Pattern: "customer.ssn", Level: Critical}}
	c := NewRuleClassifier(rules)
	rules[0].Level = Public

	if got := c.Classify("customer.ssn"); got != Critical {
		t.Fatalf("Classify(customer.ssn) = %v, want Critical, NewRuleClassifier must copy its input", got)
	}
}
