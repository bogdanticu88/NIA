package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCounter_IncAndValue(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_test_total", "a test counter")
	if got := c.Value(); got != 0 {
		t.Fatalf("fresh counter value = %d, want 0", got)
	}
	c.Inc()
	c.Inc()
	if got := c.Value(); got != 2 {
		t.Fatalf("value after two Inc = %d, want 2", got)
	}
}

func TestCounter_LabeledValuesAreIndependent(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_test_total", "a test counter", "result")
	c.Inc("success")
	c.Inc("success")
	c.Inc("error")
	if got := c.Value("success"); got != 2 {
		t.Fatalf("success = %d, want 2", got)
	}
	if got := c.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
	if got := c.Value("never_incremented"); got != 0 {
		t.Fatalf("unincremented label value = %d, want 0", got)
	}
}

func TestCounter_WrongLabelCountPanics(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_test_total", "a test counter", "result")
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a label-value count mismatch, got none")
		}
	}()
	c.Inc() // zero values for a counter that takes one
}

func TestCounter_ConcurrentIncIsRaceSafe(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_test_total", "a test counter", "outcome")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Inc("allowed")
		}()
	}
	wg.Wait()
	if got := c.Value("allowed"); got != 100 {
		t.Fatalf("value after 100 concurrent Inc = %d, want 100", got)
	}
}

func TestRegistry_WriteText_UnlabeledCounterDefaultsToZeroLine(t *testing.T) {
	r := NewRegistry()
	r.NewCounter("nia_kills_total", "kills issued")

	var buf strings.Builder
	r.WriteText(&buf)
	out := buf.String()
	if !strings.Contains(out, "# HELP nia_kills_total kills issued") {
		t.Fatalf("got %q, want a HELP line", out)
	}
	if !strings.Contains(out, "# TYPE nia_kills_total counter") {
		t.Fatalf("got %q, want a TYPE line", out)
	}
	if !strings.Contains(out, "nia_kills_total 0") {
		t.Fatalf("got %q, want an explicit zero line for an unincremented counter", out)
	}
}

func TestRegistry_WriteText_LabeledCounterFormatsPrometheusStyle(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_gateway_requests_total", "gateway request outcomes", "outcome")
	c.Inc("allowed")
	c.Inc("allowed")
	c.Inc("denied_tool")

	var buf strings.Builder
	r.WriteText(&buf)
	out := buf.String()
	if !strings.Contains(out, `nia_gateway_requests_total{outcome="allowed"} 2`) {
		t.Fatalf("got %q, want the allowed line with value 2", out)
	}
	if !strings.Contains(out, `nia_gateway_requests_total{outcome="denied_tool"} 1`) {
		t.Fatalf("got %q, want the denied_tool line with value 1", out)
	}
}

func TestRegistry_WriteText_GaugeFuncEvaluatedAtWriteTime(t *testing.T) {
	r := NewRegistry()
	n := 3
	r.NewGaugeFunc("nia_agents_registered", "agents currently registered", func() float64 { return float64(n) })

	var buf strings.Builder
	r.WriteText(&buf)
	if !strings.Contains(buf.String(), "nia_agents_registered 3") {
		t.Fatalf("got %q, want the gauge's value at the time WriteText ran", buf.String())
	}

	n = 7
	buf.Reset()
	r.WriteText(&buf)
	if !strings.Contains(buf.String(), "nia_agents_registered 7") {
		t.Fatalf("got %q, want the gauge to reflect the updated backing value on a second write, not a cached one", buf.String())
	}
}

func TestRegistry_ServeHTTP_SetsContentTypeAndBody(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("nia_test_total", "a test counter")
	c.Inc()

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want a text/plain prefix", ct)
	}
	if !strings.Contains(rec.Body.String(), "nia_test_total 1") {
		t.Fatalf("body = %q, want the counter's value", rec.Body.String())
	}
}

func TestRegistry_WriteText_OutputSortedByMetricName(t *testing.T) {
	r := NewRegistry()
	r.NewCounter("nia_zzz_total", "last alphabetically")
	r.NewCounter("nia_aaa_total", "first alphabetically")

	var buf strings.Builder
	r.WriteText(&buf)
	out := buf.String()
	if strings.Index(out, "nia_aaa_total") > strings.Index(out, "nia_zzz_total") {
		t.Fatalf("got %q, want nia_aaa_total before nia_zzz_total regardless of registration order", out)
	}
}
