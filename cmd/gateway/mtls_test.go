package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
)

// These tests do real TLS handshakes against a real listener with a real
// CA. Nothing here simulates certificate verification: the chain
// building, expiry checking and signature validation are Go's TLS stack
// doing the thing a deployment would rely on, which is the only way to
// know the configuration is right rather than the test being generous.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a client certificate signed by this CA. notBefore and
// notAfter are explicit so a test can produce an expired one without
// waiting for time to pass.
func (ca *testCA) issue(t *testing.T, commonName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

// serverCert is the gateway's own certificate, signed by the same CA so
// the test client can verify it.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "nia-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return c
}

// mtlsTestGateway is a gateway served over real TLS with client
// certificate verification enabled.
type mtlsTestGateway struct {
	gateway *gateway
	creds   *credentials.InMemoryStore
	pol     *policy.InMemoryClient
	ca      *testCA
	server  *httptest.Server
}

func newMTLSTestGateway(t *testing.T) *mtlsTestGateway {
	t.Helper()
	ca := newTestCA(t, "nia-test-ca")
	pol := policy.NewInMemoryClient()
	creds := credentials.NewInMemoryStore()

	g, _ := newTestGateway(pol)
	g.resolver = chainResolver{resolvers: []identity.Resolver{
		mtlsResolver{creds: creds, pol: pol},
		credentialResolver{creds: creds, pol: pol},
	}}

	srv := httptest.NewUnstartedServer(g.routes())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientCAs:    ca.pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &mtlsTestGateway{gateway: g, creds: creds, pol: pol, ca: ca, server: srv}
}

// clientWith builds an HTTPS client presenting the given certificate, or
// none when cert is the zero value.
func (m *mtlsTestGateway) clientWith(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: m.ca.pool, ServerName: "127.0.0.1"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

// call makes an authorized-shaped tool call and returns the status, plus
// any extra headers the caller wants to try.
func (m *mtlsTestGateway) call(t *testing.T, client *http.Client, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, m.server.URL+"/tools/invoice.read/call", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func (m *mtlsTestGateway) bind(t *testing.T, cert tls.Certificate, agentRef string, grants ...policy.Grant) {
	t.Helper()
	if _, err := m.creds.BindCertificate(t.Context(), agentRef, credentials.ThumbprintOf(cert.Certificate[0])); err != nil {
		t.Fatalf("BindCertificate: %v", err)
	}
	if len(grants) > 0 {
		if err := m.pol.WriteGrants(t.Context(), agentRef, grants); err != nil {
			t.Fatalf("WriteGrants: %v", err)
		}
	}
}

// 1. A valid CA-signed certificate, bound to an agent, authenticates.
func TestMTLS_ValidBoundCertificateAuthenticates(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, cert, "agent:billing", policy.GrantForTool("invoice.read"))

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", status, body)
	}
	if !strings.Contains(body, "agent:billing") {
		t.Fatalf("body = %s, want the agent the certificate is bound to", body)
	}
}

// 2. A certificate from a CA the gateway does not trust does not
// authenticate.
//
// Worth recording how, because it is not what it first looks like. The
// server advertises its acceptable client CAs in the CertificateRequest,
// and Go's TLS client will not send a certificate that does not chain to
// one of them, so the request arrives with no client certificate at all
// and is refused as unauthenticated. A client that forced the
// certificate anyway would fail the handshake instead, because
// VerifyClientCertIfGiven verifies what is given. Either way the
// certificate never authenticates, which is the property that matters;
// asserting one specific mechanism would be asserting a detail of the
// client rather than of this gateway.
func TestMTLS_UnknownCAIsRejected(t *testing.T) {
	m := newMTLSTestGateway(t)
	other := newTestCA(t, "some-other-ca")
	cert := other.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// Bound by thumbprint, to prove the refusal is about the chain and
	// not about the binding being missing.
	m.bind(t, cert, "agent:billing", policy.GrantForTool("invoice.read"))

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status == http.StatusOK {
		t.Fatalf("a certificate from an untrusted CA authenticated: %s", body)
	}
	// 0 means the handshake failed, 401 means it was never sent and the
	// request arrived unauthenticated. Both are refusals.
	if status != 0 && status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want the request refused: %s", status, body)
	}
}

// 3. An expired certificate fails.
func TestMTLS_ExpiredCertificateIsRejected(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	m.bind(t, cert, "agent:billing", policy.GrantForTool("invoice.read"))

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status == http.StatusOK {
		t.Fatalf("an expired certificate authenticated: %s", body)
	}
}

// 4. A certificate whose chain does not validate fails. Here the client
// presents a leaf signed by an intermediate the gateway has never seen,
// so no chain to a trusted root can be built.
func TestMTLS_InvalidChainIsRejected(t *testing.T) {
	m := newMTLSTestGateway(t)
	intermediate := newTestCA(t, "unknown-intermediate")
	cert := intermediate.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, cert, "agent:billing", policy.GrantForTool("invoice.read"))

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status == http.StatusOK {
		t.Fatalf("a certificate with no chain to a trusted root authenticated: %s", body)
	}
}

// 5. A valid certificate with no NHI binding does not authenticate. This
// is the one that matters most: a trusted CA vouches for the key, it
// says nothing about which agent is calling.
func TestMTLS_ValidCertificateWithNoBindingDoesNotAuthenticate(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "someone-else", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	// Deliberately not bound.

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a valid but unbound certificate: %s", status, body)
	}
}

// 6. A certificate bound to agent A authenticates as agent A, and its
// authorization is agent A's.
func TestMTLS_CertificateAuthenticatesAsTheBoundAgent(t *testing.T) {
	m := newMTLSTestGateway(t)
	certA := m.ca.issue(t, "agent-a", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	certB := m.ca.issue(t, "agent-b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, certA, "agent:a", policy.GrantForTool("invoice.read"))
	m.bind(t, certB, "agent:b") // bound, but granted nothing

	status, body := m.call(t, m.clientWith(&certA), nil)
	if status != http.StatusOK || !strings.Contains(body, "agent:a") {
		t.Fatalf("certificate A: status %d body %s, want agent:a authorized", status, body)
	}

	status, body = m.call(t, m.clientWith(&certB), nil)
	if status != http.StatusForbidden {
		t.Fatalf("certificate B: status %d body %s, want 403, it is a different agent with different grants", status, body)
	}
}

// 7. A caller cannot override the certificate identity with a header.
func TestMTLS_HeadersCannotOverrideTheCertificateIdentity(t *testing.T) {
	m := newMTLSTestGateway(t)
	certB := m.ca.issue(t, "agent-b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, certB, "agent:b") // no grants

	// Every header shape an implementation might have been tempted to
	// trust, plus a bearer credential for an agent that is granted.
	granted, secret, err := m.creds.Issue(t.Context(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	headers := map[string]string{
		"X-Agent-Ref":              "agent:billing",
		"X-Client-Cert":            "whatever",
		"X-Client-Cert-Thumbprint": credentials.ThumbprintOf(m.ca.cert.Raw),
		"X-Forwarded-Client-Cert":  "Hash=" + credentials.ThumbprintOf(m.ca.cert.Raw),
		"Authorization":            "Bearer " + granted.ID + "." + secret,
	}

	status, body := m.call(t, m.clientWith(&certB), headers)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d body %s, want 403: the connection's certificate identifies agent:b, and no header may change that", status, body)
	}
	if strings.Contains(body, "agent:billing") {
		t.Fatalf("body = %s, a header changed the authenticated identity", body)
	}
}

// 8. A revoked certificate binding stops authenticating, with no change
// to the certificate itself.
func TestMTLS_RevokedBindingIsRejected(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, cert, "agent:billing", policy.GrantForTool("invoice.read"))

	if status, body := m.call(t, m.clientWith(&cert), nil); status != http.StatusOK {
		t.Fatalf("status = %d before revocation, want 200: %s", status, body)
	}

	bound, err := m.creds.VerifyCertificate(t.Context(), credentials.ThumbprintOf(cert.Certificate[0]))
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if err := m.creds.Revoke(t.Context(), bound.ID, "bogdan", "key suspected compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	status, body := m.call(t, m.clientWith(&cert), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d after revoking the binding, want 401: %s", status, body)
	}
}

// 9. The thumbprint is derived from the certificate actually presented.
// Proven by binding a thumbprint computed independently from the DER
// bytes and confirming the gateway resolves the same one.
func TestMTLS_ThumbprintComesFromThePresentedCertificate(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	independent := credentials.ThumbprintOf(cert.Certificate[0])
	if len(independent) != 64 {
		t.Fatalf("thumbprint %q is not a hex SHA-256", independent)
	}
	if _, err := m.creds.BindCertificate(t.Context(), "agent:billing", independent); err != nil {
		t.Fatalf("BindCertificate: %v", err)
	}
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	if status, body := m.call(t, m.clientWith(&cert), nil); status != http.StatusOK {
		t.Fatalf("status = %d, want 200: the gateway's thumbprint must match one computed from the same DER bytes: %s", status, body)
	}

	// And a different certificate, even for the same subject name, does
	// not match that thumbprint.
	other := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if credentials.ThumbprintOf(other.Certificate[0]) == independent {
		t.Fatal("two different certificates produced the same thumbprint")
	}
}

// 10. A different certificate cannot impersonate an existing binding
// unless it is explicitly bound too. Same subject, same CA, different
// key: everything a naive implementation might match on is identical.
func TestMTLS_ADifferentCertificateCannotImpersonateABinding(t *testing.T) {
	m := newMTLSTestGateway(t)
	bound := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, bound, "agent:billing", policy.GrantForTool("invoice.read"))

	impostor := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	status, body := m.call(t, m.clientWith(&impostor), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a second certificate with the same subject from the same CA is still a different certificate: %s", status, body)
	}

	// Explicitly binding it too is what makes it work, which is the
	// "unless explicitly configured" half.
	if _, err := m.creds.BindCertificate(t.Context(), "agent:billing", credentials.ThumbprintOf(impostor.Certificate[0])); err != nil {
		t.Fatalf("BindCertificate: %v", err)
	}
	if status, body := m.call(t, m.clientWith(&impostor), nil); status != http.StatusOK {
		t.Fatalf("status = %d after binding the second certificate, want 200: %s", status, body)
	}
}

func TestMTLS_ABindingCannotBeMovedToAnotherAgentSilently(t *testing.T) {
	m := newMTLSTestGateway(t)
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, cert, "agent:billing")

	_, err := m.creds.BindCertificate(t.Context(), "agent:payroll", credentials.ThumbprintOf(cert.Certificate[0]))
	if err == nil {
		t.Fatal("a bound certificate was silently rebound to a different agent")
	}
	if !strings.Contains(err.Error(), "agent:billing") {
		t.Fatalf("err = %v, want it to name the agent it is already bound to", err)
	}
}

// 11. Bearer and certificate authentication reach the same authorization
// controls. Neither is a side door.
func TestMTLS_BearerAndCertificateGoThroughTheSameAuthorization(t *testing.T) {
	m := newMTLSTestGateway(t)

	// Same agent, two ways in, and no grants for the tool.
	cert := m.ca.issue(t, "agent-billing", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	m.bind(t, cert, "agent:billing")
	bearer, secret, err := m.creds.Issue(t.Context(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	bearerHeader := map[string]string{"Authorization": "Bearer " + bearer.ID + "." + secret}

	if status, _ := m.call(t, m.clientWith(&cert), nil); status != http.StatusForbidden {
		t.Fatalf("certificate path status = %d, want 403 with no grant", status)
	}
	if status, _ := m.call(t, m.clientWith(nil), bearerHeader); status != http.StatusForbidden {
		t.Fatalf("bearer path status = %d, want 403 with no grant", status)
	}

	// Grant it, and both start working, which proves the 403s above were
	// the same check and not two different failures.
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if status, body := m.call(t, m.clientWith(&cert), nil); status != http.StatusOK {
		t.Fatalf("certificate path status = %d after the grant, want 200: %s", status, body)
	}
	if status, body := m.call(t, m.clientWith(nil), bearerHeader); status != http.StatusOK {
		t.Fatalf("bearer path status = %d after the grant, want 200: %s", status, body)
	}

	// And a kill stops both, which is the containment half of the same
	// question.
	if _, err := m.pol.Kill(t.Context(), "agent:billing", "INC-1", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if status, _ := m.call(t, m.clientWith(&cert), nil); status != http.StatusUnauthorized {
		t.Fatalf("certificate path status = %d after the kill, want 401", status)
	}
	if status, _ := m.call(t, m.clientWith(nil), bearerHeader); status != http.StatusUnauthorized {
		t.Fatalf("bearer path status = %d after the kill, want 401", status)
	}
}

// A connection with no client certificate still authenticates by bearer,
// which is what makes the two mechanisms coexist on one listener.
func TestMTLS_NoCertificateFallsBackToBearer(t *testing.T) {
	m := newMTLSTestGateway(t)
	bearer, secret, err := m.creds.Issue(t.Context(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	status, body := m.call(t, m.clientWith(nil), map[string]string{"Authorization": "Bearer " + bearer.ID + "." + secret})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a bearer credential over TLS with no client certificate: %s", status, body)
	}
}

func TestThumbprintOf_IsHexSHA256OfTheDERBytes(t *testing.T) {
	ca := newTestCA(t, "x")
	cert := ca.issue(t, "y", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	got := credentials.ThumbprintOf(cert.Certificate[0])
	if len(got) != 64 {
		t.Fatalf("thumbprint = %q, want 64 hex characters", got)
	}
	if got != credentials.ThumbprintOf(cert.Certificate[0]) {
		t.Fatal("thumbprint is not deterministic")
	}
	if got == credentials.ThumbprintOf(ca.cert.Raw) {
		t.Fatal("the leaf and the CA produced the same thumbprint")
	}
}
