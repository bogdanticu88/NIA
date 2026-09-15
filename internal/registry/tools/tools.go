// Package tools is the catalog side of tool registration and MCP
// integration: what tools exist, what they do, and how risky calling
// them is. The gateway (cmd/gateway) consults this at request time to
// know what it's even mediating access to; internal/policy is what
// decides whether a given agent may call a given tool.
package tools

import (
	"context"
	"errors"
	"sync"
)

// RiskClass is a coarse, human-assigned classification of how much
// damage a tool can do if misused. Feeds internal/risk when scoring a
// call: a Destructive tool called by a newly registered agent is a very
// different signal than a ReadOnly tool called by the same agent.
type RiskClass string

const (
	RiskReadOnly    RiskClass = "read_only"
	RiskWrite       RiskClass = "write"
	RiskDestructive RiskClass = "destructive"
)

// Tool is one entry in the catalog. Transport is how the gateway
// reaches it, e.g. "mcp", "http", "grpc"; ties this catalog directly
// to the MCP integration item in the brief without MCP being a special
// case of the model.
type Tool struct {
	Name        string
	Description string
	Transport   string
	RiskClass   RiskClass
	Owner       string // human or team accountable for this tool
}

var ErrAlreadyRegistered = errors.New("tools: already registered")
var ErrNotFound = errors.New("tools: not found")

// Catalog is the tool registry.
type Catalog interface {
	Register(ctx context.Context, tool Tool) error
	Get(ctx context.Context, name string) (Tool, error)
	List(ctx context.Context) ([]Tool, error)
}

// InMemoryCatalog is the reference implementation.
type InMemoryCatalog struct {
	mu    sync.Mutex
	tools map[string]Tool
}

func NewInMemoryCatalog() *InMemoryCatalog {
	return &InMemoryCatalog{tools: make(map[string]Tool)}
}

func (c *InMemoryCatalog) Register(_ context.Context, tool Tool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.tools[tool.Name]; exists {
		return ErrAlreadyRegistered
	}
	c.tools[tool.Name] = tool
	return nil
}

func (c *InMemoryCatalog) Get(_ context.Context, name string) (Tool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tools[name]
	if !ok {
		return Tool{}, ErrNotFound
	}
	return t, nil
}

func (c *InMemoryCatalog) List(_ context.Context) ([]Tool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Tool, 0, len(c.tools))
	for _, t := range c.tools {
		out = append(out, t)
	}
	return out, nil
}

var _ Catalog = (*InMemoryCatalog)(nil)
