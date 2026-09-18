package risk

import (
	"context"
	"sync"
	"time"
)

// Observation is what a CallHistory knew about an agent immediately
// before the call being scored, returned by the same call that records
// it. One method does both on purpose: two concurrent first calls to
// the same tool must not both come back novel and double-count the
// signal, and splitting this into a read then a write reintroduces
// exactly that race across processes even when each process is
// internally locked.
//
// Everything here describes the state *before* the call. RecentCalls
// does not count the call being observed, so a threshold of 10 means
// "the eleventh call inside the window is the one that fires."
type Observation struct {
	// NovelTool: this agent had never called this tool before.
	NovelTool bool

	// NovelTransition: this agent had made at least one call before,
	// to a different tool, and had never gone from that tool to this
	// one. False for an agent's very first call, where there is no
	// transition yet, and false for a repeat of a pair already seen.
	//
	// Also false when the previous call named this same tool. Calling
	// one tool twice in a row is the most ordinary thing an agent does,
	// and counting the first repeat of every tool as a new ordering
	// would fire this on essentially every agent's second call. An
	// agent hammering one tool is a volume signal, not a sequence one,
	// and RecentCalls is what covers that. This is the cheapest
	// honest sequence signal: it does not model an agent's whole call
	// graph, it notices the agent doing something in an order it has
	// never done before, which is the shape a hijacked agent reusing
	// familiar tools in an unfamiliar order actually has.
	NovelTransition bool

	// RecentCalls is how many calls this agent made inside the window
	// ending at the observed call's timestamp, not counting that call.
	RecentCalls int
}

// CallHistory is the per-agent behavioural memory HistoryScorer scores
// against. It is deliberately not a general event store: three specific
// questions, answered in one atomic step alongside recording the call
// that prompted them.
//
// Two implementations. InMemoryCallHistory is the default and behaves
// the way the scorer always has, per process and lost on restart.
// PostgresCallHistory (postgres_history.go) is shared, which matters
// more here than it looks: before it, a gateway replica's idea of
// "novel" was its own, so the same tool counted as novel once per
// replica and once more after every restart, inflating a risk total
// that internal/monitoring's PostgresRiskStore was otherwise careful to
// share correctly. Sharing the total while fragmenting its inputs is
// not actually sharing the decision.
type CallHistory interface {
	Observe(ctx context.Context, agentRef, tool string, at time.Time, window time.Duration) (Observation, error)
}

// InMemoryCallHistory is the reference implementation: one mutex, three
// maps, no external dependency. Retains every (agent, tool) pair and
// every (previous tool, tool) transition it has ever seen, plus the
// timestamps of recent calls, trimmed to the window on each Observe so
// a long-running process doesn't accumulate unbounded timestamps for a
// busy agent.
type InMemoryCallHistory struct {
	mu          sync.Mutex
	seenTools   map[string]map[string]struct{} // agentRef -> tools already called
	transitions map[string]map[string]struct{} // agentRef -> "prev\x00next" pairs already seen
	lastTool    map[string]string              // agentRef -> the tool its previous call named
	recent      map[string][]time.Time         // agentRef -> timestamps inside the window
}

func NewInMemoryCallHistory() *InMemoryCallHistory {
	return &InMemoryCallHistory{
		seenTools:   make(map[string]map[string]struct{}),
		transitions: make(map[string]map[string]struct{}),
		lastTool:    make(map[string]string),
		recent:      make(map[string][]time.Time),
	}
}

func (h *InMemoryCallHistory) Observe(_ context.Context, agentRef, tool string, at time.Time, window time.Duration) (Observation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var obs Observation

	seen, ok := h.seenTools[agentRef]
	if !ok {
		seen = make(map[string]struct{})
		h.seenTools[agentRef] = seen
	}
	if _, called := seen[tool]; !called {
		obs.NovelTool = true
		seen[tool] = struct{}{}
	}

	if prev, hadPrevious := h.lastTool[agentRef]; hadPrevious && prev != tool {
		pairs, ok := h.transitions[agentRef]
		if !ok {
			pairs = make(map[string]struct{})
			h.transitions[agentRef] = pairs
		}
		key := prev + "\x00" + tool
		if _, seenPair := pairs[key]; !seenPair {
			obs.NovelTransition = true
			pairs[key] = struct{}{}
		}
	}
	h.lastTool[agentRef] = tool

	if window > 0 {
		cutoff := at.Add(-window)
		kept := h.recent[agentRef][:0]
		for _, ts := range h.recent[agentRef] {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		obs.RecentCalls = len(kept)
		h.recent[agentRef] = append(kept, at)
	}

	return obs, nil
}

var _ CallHistory = (*InMemoryCallHistory)(nil)
