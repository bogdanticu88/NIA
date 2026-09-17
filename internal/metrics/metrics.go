// Package metrics is a small, dependency-free counter and gauge
// registry, exposed as Prometheus text exposition format over an HTTP
// handler. This codebase has exactly one external dependency today,
// lib/pq, and only when NIA_AUDIT_DATABASE_URL is set. Prometheus's own
// text format is a handful of plain lines per metric, not a reason to
// pull in github.com/prometheus/client_golang for the eight or so
// counters and gauges cmd/api and cmd/gateway actually need. If this
// ever grows into needing histograms, summaries, or a pull-based
// exporter with more machinery than a registry and a text writer, that
// growth is the trigger to switch to the real client, not something to
// build ahead of time here.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing value, optionally broken down
// by one or more label values (a result, an outcome, an action). Safe
// for concurrent use. There is no Dec: everything this codebase counts
// is an event that happened, not a level that can go back down, that's
// what Gauge and GaugeFunc are for.
type Counter struct {
	name       string
	help       string
	labelNames []string

	mu     sync.Mutex
	values map[string]*int64 // joined label values -> count
	order  []string          // insertion order of the keys above, for deterministic output
}

func newCounter(name, help string, labelNames ...string) *Counter {
	return &Counter{name: name, help: help, labelNames: labelNames, values: make(map[string]*int64)}
}

// Inc increments the counter for the given label values by one. The
// number of values must match the number of label names the counter was
// created with; a mismatch is a programming error, not something a
// caller should have to check for at every call site, so this panics
// rather than silently mislabeling data, the same posture Go's own
// fmt.Sprintf takes on a verb/argument mismatch.
func (c *Counter) Inc(labelValues ...string) {
	if len(labelValues) != len(c.labelNames) {
		panic(fmt.Sprintf("metrics: counter %s takes %d label value(s), got %d", c.name, len(c.labelNames), len(labelValues)))
	}
	key := strings.Join(labelValues, "\x1f")
	c.mu.Lock()
	p, ok := c.values[key]
	if !ok {
		var v int64
		p = &v
		c.values[key] = p
		c.order = append(c.order, key)
	}
	c.mu.Unlock()
	atomic.AddInt64(p, 1)
}

// Value returns the current count for a given label-value tuple, 0 if
// it's never been incremented. Exported mainly for tests, reading a
// counter back is otherwise done through WriteText/ServeHTTP.
func (c *Counter) Value(labelValues ...string) int64 {
	key := strings.Join(labelValues, "\x1f")
	c.mu.Lock()
	p, ok := c.values[key]
	c.mu.Unlock()
	if !ok {
		return 0
	}
	return atomic.LoadInt64(p)
}

func (c *Counter) writeText(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	c.mu.Lock()
	keys := append([]string(nil), c.order...)
	c.mu.Unlock()
	if len(keys) == 0 {
		// A counter nobody has incremented yet still gets a line at
		// zero rather than being absent, so a dashboard querying this
		// metric from the first scrape doesn't see a gap it has to
		// explain, this is what Prometheus client libraries do too for
		// a label-less counter, extended here to the zero-value case of
		// a labeled one with no observations yet.
		if len(c.labelNames) == 0 {
			fmt.Fprintf(w, "%s 0\n", c.name)
		}
		return
	}
	for _, key := range keys {
		labelValues := strings.Split(key, "\x1f")
		c.mu.Lock()
		v := atomic.LoadInt64(c.values[key])
		c.mu.Unlock()
		fmt.Fprintf(w, "%s%s %d\n", c.name, formatLabels(c.labelNames, labelValues), v)
	}
}

// GaugeFunc is a metric evaluated at scrape time rather than tracked
// incrementally, for a value that's cheaper to compute by asking the
// current state (how many agents are registered right now) than to keep
// in sync with every place that state can change.
type GaugeFunc struct {
	name string
	help string
	fn   func() float64
}

func (g *GaugeFunc) writeText(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", g.name, g.help, g.name, g.name, g.fn())
}

func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%q", n, values[i])
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Registry holds every counter and gauge one process exposes. cmd/api
// and cmd/gateway each own one, built at startup, never shared between
// processes, in-memory only, the same scaffold-honest posture as every
// other in-memory store in this codebase: a restart loses the counts,
// there is no persistence, and a second replica keeps its own separate
// numbers, not aggregated with any other instance's.
type Registry struct {
	mu       sync.Mutex
	counters []*Counter
	gauges   []*GaugeFunc
}

func NewRegistry() *Registry {
	return &Registry{}
}

// NewCounter creates and registers a counter. Call this at startup,
// once per metric, and keep the returned *Counter to call Inc on as the
// events it counts happen.
func (r *Registry) NewCounter(name, help string, labelNames ...string) *Counter {
	c := newCounter(name, help, labelNames...)
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// NewGaugeFunc registers a gauge backed by fn, called fresh on every
// scrape. fn must be cheap and safe to call concurrently with whatever
// else is happening in the process, it's typically a thin wrapper over
// an existing store's List/Len.
func (r *Registry) NewGaugeFunc(name, help string, fn func() float64) {
	r.mu.Lock()
	r.gauges = append(r.gauges, &GaugeFunc{name: name, help: help, fn: fn})
	r.mu.Unlock()
}

// WriteText renders every registered metric in Prometheus text exposition
// format (the same format a real Prometheus server's /metrics scrape
// expects), counters first in registration order, then gauges.
func (r *Registry) WriteText(w io.Writer) {
	r.mu.Lock()
	counters := append([]*Counter(nil), r.counters...)
	gauges := append([]*GaugeFunc(nil), r.gauges...)
	r.mu.Unlock()

	// Registration order is deterministic (it's the order NewCounter/
	// NewGaugeFunc were called at startup), sorting by name on top of
	// that keeps a diff between two scrapes readable and keeps tests
	// that check for a substring simple, without depending on call order
	// staying exactly the same as the codebase grows more metrics.
	sort.Slice(counters, func(i, j int) bool { return counters[i].name < counters[j].name })
	sort.Slice(gauges, func(i, j int) bool { return gauges[i].name < gauges[j].name })

	for _, c := range counters {
		c.writeText(w)
	}
	for _, g := range gauges {
		g.writeText(w)
	}
}

// ServeHTTP makes a Registry usable directly as the handler for GET
// /metrics.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	r.WriteText(w)
}
