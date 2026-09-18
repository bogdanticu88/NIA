package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

func ssnClassifier(t *testing.T) sensitivity.Classifier {
	t.Helper()
	return sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
		{Pattern: "ssn", Level: sensitivity.Critical},
		{Pattern: "salary", Level: sensitivity.Sensitive},
	})
}

func TestSensitiveResponseFields_FindsADeclaredFieldByPathAndByName(t *testing.T) {
	body := []byte(`{"customers":[{"name":"a","ssn":"111"},{"name":"b","ssn":"222"}]}`)
	got := sensitiveResponseFields(body, ssnClassifier(t))
	if len(got) != 1 || got[0] != "customers.ssn" {
		t.Fatalf("got %v, want exactly customers.ssn once for a list of rows", got)
	}
}

func TestSensitiveResponseFields_IgnoresUndeclaredFields(t *testing.T) {
	body := []byte(`{"customers":[{"name":"a","email":"x@y.z"}]}`)
	if got := sensitiveResponseFields(body, ssnClassifier(t)); len(got) != 0 {
		t.Fatalf("got %v, want nothing: this matches declared rules, it does not guess", got)
	}
}

func TestSensitiveResponseFields_NonJSONOrEmptyBodyIsNothing(t *testing.T) {
	c := ssnClassifier(t)
	for _, body := range [][]byte{nil, {}, []byte("not json at all"), []byte("\x00\x01\x02")} {
		if got := sensitiveResponseFields(body, c); len(got) != 0 {
			t.Fatalf("body %q produced %v, want nothing: this walks structure, it does not grep", body, got)
		}
	}
}

func TestSensitiveResponseFields_NilClassifierIsNothing(t *testing.T) {
	if got := sensitiveResponseFields([]byte(`{"ssn":"111"}`), nil); len(got) != 0 {
		t.Fatalf("got %v with no classifier configured, want nothing", got)
	}
}

// TestSensitiveResponseFields_DepthIsBounded covers the hot-path safety
// property: a response body is attacker-influenced input and an
// unbounded recursive walk is a stack exhaustion waiting for a
// downstream that returns deeply nested JSON.
func TestSensitiveResponseFields_DepthIsBounded(t *testing.T) {
	deep := `{"ssn":"top"`
	for i := 0; i < 200; i++ {
		deep += `,"a":{"ssn":"nested"`
	}
	for i := 0; i < 200; i++ {
		deep += `}`
	}
	deep += `}`

	got := sensitiveResponseFields([]byte(deep), ssnClassifier(t))
	if len(got) == 0 {
		t.Fatal("the top-level field was missed entirely")
	}
	for _, path := range got {
		if strings.Count(path, ".") > maxResponseInspectionDepth {
			t.Fatalf("path %q is deeper than the bound, the walk is not stopping", path)
		}
	}
}

func TestFormatFieldList_TruncatesAndSaysSo(t *testing.T) {
	many := make([]string, 25)
	for i := range many {
		many[i] = "f" + itoa(i)
	}
	out := formatFieldList(many)
	if !strings.Contains(out, "15 more") {
		t.Fatalf("formatFieldList = %q, want it to say how many it left out", out)
	}
	if len(formatFieldList([]string{"a", "b"})) == 0 {
		t.Fatal("a short list rendered empty")
	}
}

// forwardingGateway wires a gateway against a downstream that returns
// the given body, with the tool granted, so the only thing under test is
// what happens to the response.
func forwardingGateway(t *testing.T, responseBody string) (*gateway, *audit.InMemorySink) {
	t.Helper()
	pol := policy.NewInMemoryClient()
	if err := pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("database.query")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g, sink := newTestGateway(pol)
	g.sensitive = ssnClassifier(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(srv.Close)
	g.forwarder = NewHTTPForwarder(srv.URL)
	return g, sink
}

func TestInspectResponseFields_UngrantedSensitiveFieldIsAudited(t *testing.T) {
	g, sink := forwardingGateway(t, `{"rows":[{"name":"a","ssn":"111"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/tools/database.query/call", strings.NewReader(`{}`))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the call itself was authorized: %s", rec.Code, rec.Body.String())
	}
	assertAudited(t, sink, "gateway.downstream_ungranted_fields", "rows.ssn")
}

func TestInspectResponseFields_GrantedSensitiveFieldIsRecordedSeparately(t *testing.T) {
	g, sink := forwardingGateway(t, `{"rows":[{"ssn":"111"}]}`)
	if err := g.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForData("rows.ssn")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tools/database.query/call", strings.NewReader(`{}`))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	g.routes().ServeHTTP(httptest.NewRecorder(), req)

	assertAudited(t, sink, "gateway.downstream_sensitive_fields", "rows.ssn")
	assertNotAudited(t, sink, "gateway.downstream_ungranted_fields")
}

func TestInspectResponseFields_NothingSensitiveIsSilent(t *testing.T) {
	g, sink := forwardingGateway(t, `{"rows":[{"name":"a","email":"x@y.z"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/tools/database.query/call", strings.NewReader(`{}`))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	g.routes().ServeHTTP(httptest.NewRecorder(), req)

	assertNotAudited(t, sink, "gateway.downstream_ungranted_fields")
	assertNotAudited(t, sink, "gateway.downstream_sensitive_fields")
}

func assertAudited(t *testing.T, sink *audit.InMemorySink, action, mustContain string) {
	t.Helper()
	events, err := sink.Recent(t.Context(), 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, mustContain) {
			return
		}
	}
	t.Fatalf("no %s event containing %q, events: %+v", action, mustContain, events)
}

func assertNotAudited(t *testing.T, sink *audit.InMemorySink, action string) {
	t.Helper()
	events, err := sink.Recent(t.Context(), 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	for _, e := range events {
		if e.Action == action {
			t.Fatalf("unexpected %s event: %+v", action, e)
		}
	}
}

// TestInspectResponseFields_UngrantedFieldFeedsTheRiskTotal is the part
// with consequences. Auditing a response-side finding and stopping there
// would make it a log line; scoring it means an agent pulling fields it
// was never granted accumulates toward the same containment thresholds
// the request side feeds.
func TestInspectResponseFields_UngrantedFieldFeedsTheRiskTotal(t *testing.T) {
	pol := policy.NewInMemoryClient()
	if err := pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("database.query")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	// Kill threshold low enough that one ungranted critical field
	// crosses it, so the test asserts containment rather than a number.
	g, sink := newTestGatewayWithMonitoring(pol, fakeScorer{value: 5}, monitoring.Threshold{FlagAt: 1, RevokeAt: 100, KillAt: 6})
	g.sensitive = ssnClassifier(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[{"ssn":"111"}]}`))
	}))
	defer srv.Close()
	g.forwarder = NewHTTPForwarder(srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/tools/database.query/call", strings.NewReader(`{}`))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	g.routes().ServeHTTP(httptest.NewRecorder(), req)

	assertAudited(t, sink, "gateway.downstream_ungranted_fields", "rows.ssn")

	killed, err := pol.IsKilled(t.Context(), "agent:billing")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("the response-side finding did not reach containment, it is a log line rather than a control")
	}
}
