package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/credentials"
)

func decodeCredential(t *testing.T, rec *httptest.ResponseRecorder) credentials.Credential {
	t.Helper()
	var cred credentials.Credential
	if err := json.NewDecoder(rec.Body).Decode(&cred); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return cred
}

func decodeCredentials(t *testing.T, rec *httptest.ResponseRecorder) []credentials.Credential {
	t.Helper()
	var creds []credentials.Credential
	if err := json.NewDecoder(rec.Body).Decode(&creds); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return creds
}

func TestHandleIssueCredential_RequiresRegisteredAgent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"kind":"api_key"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:ghost/credentials", strings.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unregistered agent: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleIssueCredential_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"smart_card"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown kind: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleIssueCredential_WritesAuditEvent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	issueReq := `{"kind":"api_key","operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(issueReq)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	cred := decodeCredential(t, rec)
	if cred.ID == "" || cred.AgentRef != "agent:billing" || cred.Kind != credentials.KindAPIKey {
		t.Fatalf("got %+v, want a populated api_key credential for agent:billing", cred)
	}
	if cred.Status != credentials.StatusActive {
		t.Fatalf("Status = %q, want active", cred.Status)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 2 || events[1].Action != "credential.issued" {
		t.Fatalf("got %v, want agent.registered followed by credential.issued", events)
	}
}

func TestHandleListCredentials_OnlyReturnsThatAgents(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	for _, ref := range []string{"agent:billing", "agent:reporting"} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"`+ref+`","owner":"bogdan"}`)))
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/"+ref+"/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	creds := decodeCredentials(t, rec)
	if len(creds) != 1 || creds[0].AgentRef != "agent:billing" {
		t.Fatalf("got %v, want exactly one credential for agent:billing", creds)
	}
}

func TestHandleRevokeCredential_WritesAuditEventAndUpdatesStatus(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred := decodeCredential(t, rec)

	rec = httptest.NewRecorder()
	revokeReq := `{"revoked_by":"bogdan","reason":"key leaked in a log"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", strings.NewReader(revokeReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	updated := decodeCredential(t, rec)
	if updated.Status != credentials.StatusRevoked || updated.RevokedBy != "bogdan" {
		t.Fatalf("got %+v, want a revoked credential attributed to bogdan", updated)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 3 || events[2].Action != "credential.revoked" {
		t.Fatalf("got %v, want registered, issued, then credential.revoked", events)
	}
}

func TestHandleRevokeCredential_NotFound(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/does-not-exist/revoke", strings.NewReader(`{"revoked_by":"bogdan"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown credential id: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleDisableCredential_ThenEnable_RestoresActiveStatus(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred := decodeCredential(t, rec)

	rec = httptest.NewRecorder()
	disableReq := `{"disabled_by":"bogdan","reason":"rotating keys, pausing the old one first"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/disable", strings.NewReader(disableReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	disabled := decodeCredential(t, rec)
	if disabled.Status != credentials.StatusDisabled || disabled.DisabledBy != "bogdan" {
		t.Fatalf("got %+v, want a disabled credential attributed to bogdan", disabled)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/enable", strings.NewReader(`{"enabled_by":"bogdan"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	enabled := decodeCredential(t, rec)
	if enabled.Status != credentials.StatusActive {
		t.Fatalf("Status = %q after enable, want active", enabled.Status)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 4 || events[2].Action != "credential.disabled" || events[3].Action != "credential.enabled" {
		t.Fatalf("got %v, want registered, issued, disabled, enabled", events)
	}
}

func TestHandleEnableCredential_RefusesARevokedCredential(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred := decodeCredential(t, rec)

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", strings.NewReader(`{"revoked_by":"bogdan","reason":"compromised"}`)))

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/enable", strings.NewReader(`{"enabled_by":"bogdan"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: revocation is one-way, enable must not undo it: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRotateCredential_OldSecretStopsWorkingNewOneStarts(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	old := decodeCredential(t, rec)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+old.ID+"/rotate", strings.NewReader(`{"rotated_by":"bogdan"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	next := decodeCredential(t, rec)
	if next.ID == old.ID {
		t.Fatalf("rotate returned the same id %q, want a new credential", next.ID)
	}
	if next.RotatedFrom != old.ID {
		t.Fatalf("RotatedFrom = %q, want %q", next.RotatedFrom, old.ID)
	}

	// The atomic guarantee rotate exists for: fetch both rows back and
	// confirm the old one is Revoked (not just "replaced" in name) and
	// the new one is Active, there is never a window with both or
	// neither valid, see credentials.Store.Rotate's own doc comment.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	creds := decodeCredentials(t, rec)
	byID := map[string]credentials.Credential{}
	for _, c := range creds {
		byID[c.ID] = c
	}
	if byID[old.ID].Status != credentials.StatusRevoked {
		t.Fatalf("old credential status = %q, want revoked after rotate", byID[old.ID].Status)
	}
	if byID[old.ID].RotatedTo != next.ID {
		t.Fatalf("old credential RotatedTo = %q, want %q", byID[old.ID].RotatedTo, next.ID)
	}
	if byID[next.ID].Status != credentials.StatusActive {
		t.Fatalf("new credential status = %q, want active", byID[next.ID].Status)
	}
}

// TestCredentialResponses_NeverCarryTheSecretHash is the API-level
// half of credentials.TestCredential_JSONNeverCarriesTheSecretHash:
// that test proves the Credential type itself never serializes the
// field, this one proves it end to end through the actual handlers a
// real caller hits, issue, rotate, and list, found by actually running
// a live nia-api and reading its own response bodies, not just by
// inspecting the struct tag. See credentials.Credential.SecretHash's
// own doc comment for the exposure this closes.
func TestCredentialResponses_NeverCarryTheSecretHash(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	if strings.Contains(rec.Body.String(), "SecretHash") {
		t.Fatalf("issue response contains SecretHash: %s", rec.Body.String())
	}
	old := decodeCredential(t, rec)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+old.ID+"/rotate", strings.NewReader(`{"rotated_by":"bogdan"}`)))
	if strings.Contains(rec.Body.String(), "SecretHash") {
		t.Fatalf("rotate response contains SecretHash: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	if strings.Contains(rec.Body.String(), "SecretHash") {
		t.Fatalf("list response contains SecretHash: %s", rec.Body.String())
	}
}

func TestHandleBindCertificate_DerivesTheThumbprintFromThePEM(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents",
		strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	der := testCertificateDER(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	body, _ := json.Marshal(map[string]string{"certificate_pem": string(pemBytes)})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/certificates", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	// The thumbprint the server derived must be the one the gateway will
	// compute from the same certificate on the wire, or the binding
	// silently never matches.
	want := credentials.ThumbprintOf(der)
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("response %s does not carry the thumbprint %s derived from the certificate", rec.Body.String(), want)
	}
	if _, err := s.creds.VerifyCertificate(t.Context(), want); err != nil {
		t.Fatalf("VerifyCertificate after binding: %v", err)
	}
}

func TestHandleBindCertificate_AcceptsAColonSeparatedThumbprint(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents",
		strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	raw := credentials.ThumbprintOf(testCertificateDER(t))
	// The shape openssl prints, which is what an operator will paste.
	var spaced strings.Builder
	for i := 0; i < len(raw); i += 2 {
		if i > 0 {
			spaced.WriteString(":")
		}
		spaced.WriteString(strings.ToUpper(raw[i : i+2]))
	}

	body, _ := json.Marshal(map[string]string{"thumbprint": spaced.String()})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/certificates", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for a colon separated uppercase fingerprint: %s", rec.Code, rec.Body.String())
	}
	if _, err := s.creds.VerifyCertificate(t.Context(), raw); err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
}

func TestHandleBindCertificate_RejectsNonsense(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents",
		strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	for name, body := range map[string]string{
		"neither field":    `{}`,
		"not pem":          `{"certificate_pem":"hello"}`,
		"short thumbprint": `{"thumbprint":"abcd"}`,
		"pem of nothing":   "{\"certificate_pem\":\"-----BEGIN CERTIFICATE-----\\nZm9v\\n-----END CERTIFICATE-----\\n\"}",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/certificates", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400: %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleBindCertificate_RequiresARegisteredAgent(t *testing.T) {
	s := newTestServer()
	der := testCertificateDER(t)
	body, _ := json.Marshal(map[string]string{"thumbprint": credentials.ThumbprintOf(der)})
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:nope/certificates", bytes.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unregistered agent", rec.Code)
	}
}

// testCertificateDER mints a throwaway self-signed certificate, enough
// to have real DER bytes to hash.
func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-billing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return der
}
