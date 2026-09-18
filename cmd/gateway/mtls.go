package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
)

// Mutual TLS authentication for the gateway.
//
// The flow, and every step of it matters:
//
//	TLS client certificate -> chain and validity verified by the TLS
//	stack against a configured CA bundle -> SHA-256 thumbprint computed
//	from the certificate the peer actually presented -> explicit binding
//	to an NHI -> authorization
//
// Two of those steps are the ones that are easy to get wrong.
//
// The thumbprint is computed here, from the DER bytes in the verified
// chain, and never read from anything the caller sends. A gateway that
// accepted an X-Client-Cert-Thumbprint header would be authenticating
// whoever can set a header, which is everyone. Those headers are ignored
// by this implementation entirely, see mtlsResolver.Resolve.
//
// And a valid certificate is not an identity. A certificate signed by a
// trusted CA means the deployment trusts that CA's issuance process; it
// does not say which agent is calling. Treating the first as the second
// would make every certificate that CA ever issues, for any purpose,
// into an authenticated agent of this control plane. So a certificate
// authenticates only when an operator has explicitly bound its
// thumbprint to an agent, see credentials.Store.BindCertificate.
//
// TLS termination is at the gateway, which is the authoritative model
// here. Terminating at an ingress and forwarding the certificate in a
// header is a real deployment shape and is deliberately not supported:
// it would require a trusted-proxy boundary, a way to know a request
// genuinely came through it, and a way to stop anyone else reaching the
// port with the same headers. That is its own piece of work with its own
// failure modes, and half of it is worse than none, so it is documented
// as unsupported rather than approximated.
//
// Revocation is local and explicit: revoke the certificate binding
// through internal/credentials and the certificate stops authenticating
// on the next request, everywhere, because the binding is the thing
// being checked. CRL and OCSP are deliberately not implemented; whether
// a deployment needs them, and how it distributes revocation
// information, is a PKI decision NIA should not be making on its own.

const (
	// envTLSCert and envTLSKey turn on TLS on the gateway's listener.
	// Both or neither.
	envTLSCert = "NIA_GATEWAY_TLS_CERT"
	envTLSKey  = "NIA_GATEWAY_TLS_KEY"

	// envTLSClientCA is the bundle of CAs whose client certificates this
	// gateway will verify. Without it, TLS still works and mTLS does
	// not: there is nothing to verify a client certificate against, and
	// trusting the system roots for client authentication would mean
	// every certificate any public CA ever issued is a candidate.
	envTLSClientCA = "NIA_GATEWAY_TLS_CLIENT_CA"
)

// tlsConfigFromEnv builds the listener's TLS configuration. A nil result
// means plain HTTP, which is what every deployment before this had and
// remains the default.
func tlsConfigFromEnv() (*tls.Config, bool, error) {
	certPath := strings.TrimSpace(os.Getenv(envTLSCert))
	keyPath := strings.TrimSpace(os.Getenv(envTLSKey))
	caPath := strings.TrimSpace(os.Getenv(envTLSClientCA))

	switch {
	case certPath == "" && keyPath == "" && caPath == "":
		return nil, false, nil
	case certPath == "" || keyPath == "":
		return nil, false, fmt.Errorf("gateway: %s and %s must be set together to serve TLS", envTLSCert, envTLSKey)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("gateway: loading the TLS certificate and key: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caPath == "" {
		return cfg, false, nil
	}

	pool, err := loadCABundle(caPath)
	if err != nil {
		return nil, false, err
	}
	cfg.ClientCAs = pool

	// VerifyClientCertIfGiven rather than RequireAndVerifyClientCert, so
	// certificate and bearer authentication coexist: an agent with a
	// certificate presents one and is authenticated by it, an agent with
	// a bearer credential connects without one and is authenticated by
	// that. Requiring a certificate from everyone would make bearer
	// credentials unusable over the same listener, which is a
	// deployment decision, not a security improvement.
	//
	// The important half is what "IfGiven" does not mean: a certificate
	// that is given and fails to verify fails the handshake. There is no
	// path where an invalid certificate arrives at the application and
	// is treated as no certificate.
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	return cfg, true, nil
}

func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: reading %s (%s): %w", envTLSClientCA, path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("gateway: %s (%s) contained no usable certificates", envTLSClientCA, path)
	}
	return pool, nil
}

// mtlsResolver authenticates an agent from the client certificate
// presented during the TLS handshake.
//
// It is an identity.Resolver like credentialResolver, and deliberately
// so: both produce the same ResolvedIdentity, which is what makes
// everything downstream of authentication identical for the two. There
// is no separate authorization path for certificate-authenticated
// agents, and so no second path that could be missing a control.
type mtlsResolver struct {
	creds credentials.Store
	pol   policy.Client
}

func (m mtlsResolver) Resolve(ctx context.Context, rc identity.ResolveContext) (*identity.ResolvedIdentity, error) {
	leaf := rc.LeafCertificate()
	if leaf == nil {
		// No verified client certificate on this connection. Not an
		// error: this resolver simply has nothing to say, and a chained
		// resolver will try the next one.
		return nil, nil
	}

	// Computed from the bytes the peer actually presented and verified,
	// never from a header. See this file's own doc comment.
	thumbprint := credentials.ThumbprintOf(leaf.Raw)

	cred, err := m.creds.VerifyCertificate(ctx, thumbprint)
	if err != nil {
		if err == credentials.ErrInvalidCredential {
			// Unbound, revoked, expired or disabled. A verified
			// certificate with no binding is the important case here: it
			// proves the holder has a key a trusted CA vouched for, and
			// nothing about which agent that is, so it does not
			// authenticate.
			return nil, nil
		}
		// The store could not answer. Not "no identity", fail closed,
		// same as credentialResolver.
		return nil, err
	}

	killed, err := m.pol.IsKilled(ctx, cred.AgentRef)
	if err != nil {
		return nil, err
	}
	if killed {
		return nil, nil
	}

	return &identity.ResolvedIdentity{
		Ref:          cred.AgentRef,
		Assurance:    identity.AssuranceStrong,
		CredentialID: cred.ID,
	}, nil
}

var _ identity.Resolver = mtlsResolver{}

// chainResolver tries each resolver in order and takes the first
// identity any of them establishes.
//
// Certificate authentication goes first when both are configured: it is
// a property of the connection rather than of a header, so if a
// certificate was presented and bound, that is who the caller is, and a
// bearer credential in the same request cannot change it. That ordering
// is what stops the two mechanisms being played against each other.
//
// An error from any resolver stops the chain. A store that could not
// answer must not fall through to the next mechanism and quietly succeed
// with a weaker one.
type chainResolver struct {
	resolvers []identity.Resolver
}

func (c chainResolver) Resolve(ctx context.Context, rc identity.ResolveContext) (*identity.ResolvedIdentity, error) {
	for _, r := range c.resolvers {
		resolved, err := r.Resolve(ctx, rc)
		if err != nil {
			return nil, err
		}
		if resolved != nil {
			return resolved, nil
		}
	}
	return nil, nil
}

var _ identity.Resolver = chainResolver{}

// resolveContextFor builds the resolve context from an inbound request,
// carrying both the headers and whatever the TLS stack verified.
//
// One function, used by every entry point, so a new handler cannot
// accidentally build a context that omits the certificate and silently
// fall back to bearer authentication for a caller that presented one.
func resolveContextFor(r *http.Request) identity.ResolveContext {
	headers := map[string]string{}
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}
	rc := identity.ResolveContext{Headers: headers}
	if r.TLS != nil {
		rc.VerifiedChains = r.TLS.VerifiedChains
	}
	return rc
}
