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
//
// The token exists because cmd/api authenticates its own surface now.
// GET /tools/{name} needs the viewer permission like every other read
// there, so a reader with no credential gets 401 on every lookup and
// the gateway reports tool_lookup_error for every call, which is how
// this was found: the compose stack could not call a single tool. The
// token is the gateway's own operator credential, not the calling
// agent's, for the same reason the MCP downstream connection uses NIA's
// own credential rather than replaying the agent's.
type HTTPReader struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewHTTPReader builds a reader against baseURL, cmd/api's own address,
// e.g. http://nia-api:8080 in compose, http://localhost:8080 locally.
//
// An empty token is valid and means "send no credential", which is
// correct against a cmd/api running with NIA_ALLOW_UNAUTHENTICATED=1
// and wrong against any other, see FromEnvReader.
func NewHTTPReader(baseURL, token string) *HTTPReader {
	return &HTTPReader{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      strings.TrimSpace(token),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *HTTPReader) Get(ctx context.Context, name string) (Tool, error) {
	reqURL := c.baseURL + "/tools/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Tool{}, fmt.Errorf("tools: building request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Tool{}, fmt.Errorf("tools: GET %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Tool{}, ErrNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Named rather than folded into the generic case below, because
		// the generic message ("unexpected status 401") says nothing
		// about what to do and this one has exactly one cause.
		return Tool{}, fmt.Errorf("tools: GET %s: %d, the catalog lookup was refused: set %s to an operator token with the viewer role", reqURL, resp.StatusCode, envAPIToken)
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
