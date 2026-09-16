package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPReader implements Reader against cmd/api's own tool catalog
// endpoints (GET /tools/{name}), the same HTTP surface niactl talks to.
// This is what lets cmd/gateway, a separate process, see the tools
// cmd/api registered, the same problem the audit trail had before
// PostgresSink, solved here by pointing the gateway back at the one
// process that already owns the catalog instead of standing up a
// second shared store for a lookup this cheap and this infrequent
// relative to the hot path's actual bottleneck, the policy check.
type HTTPReader struct {
	baseURL    string
	httpClient *http.Client
}

// NewHTTPReader builds a reader against baseURL, cmd/api's own address,
// e.g. http://nia-api:8080 in compose, http://localhost:8080 locally.
func NewHTTPReader(baseURL string) *HTTPReader {
	return &HTTPReader{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *HTTPReader) Get(ctx context.Context, name string) (Tool, error) {
	reqURL := c.baseURL + "/tools/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Tool{}, fmt.Errorf("tools: building request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Tool{}, fmt.Errorf("tools: GET %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Tool{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return Tool{}, fmt.Errorf("tools: GET %s: unexpected status %d", reqURL, resp.StatusCode)
	}

	var tool Tool
	if err := json.NewDecoder(resp.Body).Decode(&tool); err != nil {
		return Tool{}, fmt.Errorf("tools: decoding response from %s: %w", reqURL, err)
	}
	return tool, nil
}

var _ Reader = (*HTTPReader)(nil)
