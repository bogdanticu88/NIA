package tools

import (
	"os"
	"strings"
)

// envAPIURL is the one environment variable this file reads. Unset
// means FromEnvReader returns a nil Reader, catalog enforcement stays
// off, cmd/gateway's existing tool-name-only check is unchanged, this
// is additive, not a stricter default nothing opted into. Set it to
// cmd/api's own address and the gateway starts rejecting calls to
// tools nobody registered, see cmd/gateway's doc comment on why that
// lookup happens over HTTP against cmd/api rather than a second shared
// store.
const envAPIURL = "NIA_TOOLS_API_URL"

// FromEnvReader builds the Reader cmd/gateway checks a tool against
// before forwarding a call. A nil Reader (both return values valid,
// error is nil) means "not configured", callers must treat that as
// "skip the check", never as "nothing is registered."
func FromEnvReader() (Reader, error) {
	base := strings.TrimSpace(os.Getenv(envAPIURL))
	if base == "" {
		return nil, nil
	}
	return NewHTTPReader(base), nil
}
