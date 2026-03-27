package traefik_certauthz_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	traefik_certauthz "github.com/wartydany/traefik-cn-authz"
)

//
// CONFIG
//

func TestConfigFailure_NoRegex(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := traefik_certauthz.New(ctx, next, cfg, "certauthz")
	if err == nil {
		t.Error("regex must be provided")
	}
}

//
// REGEX - VALID CASES
//

func TestRegexExactMatch(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^example\\.org$"

	testValidConfig(t, cfg, "example.org", "200 OK")
}

func TestRegexMultipleValidCN(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^example\\.org$|^[^.]+\\.example\\.org$"

	tests := []string{
		"example.org",
		"sub.example.org",
	}

	for _, cn := range tests {
		testValidConfig(t, cfg, cn, "200 OK")
	}
}

//
// REGEX - FAILURE CASES
//

func TestRegexExactMatchFailure(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^example\\.org$"

	testValidConfig(t, cfg, "examplexorg", "403 Forbidden")
}

func TestRegexRejectSubdomainWhenNotAllowed(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^example\\.org$"

	testValidConfig(t, cfg, "example.org.badactor.com", "403 Forbidden")
}

func TestRegexEscapedDotStillNeedsAnchors(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "example\\.org"

	testValidConfig(t, cfg, "example.org.badactor.com", "200 OK") // intentional
}

//
// REGEX - UNSAFE CONFIGURATION (DOCUMENTED BEHAVIOR)
//

func TestRegexWithoutAnchorsAllowsBypass(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "example.org"

	testValidConfig(t, cfg, "examplexorg.badactor.com", "200 OK")
}

//
// CN VALIDATION
//

func TestCNSuccess(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^[a-z][0-9a-z]{1,3}-[0-9a-zA-Z]{1,64}$"

	testValidConfig(t, cfg, "a1-test", "200 OK")
}

func TestCNFailure(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^[a-z][0-9a-z]{1,3}-[0-9a-zA-Z]{1,64}$"

	testValidConfig(t, cfg, "INVALID!", "403 Forbidden")
}

//
// NO CERT CASE
//

func TestNoCertificate(t *testing.T) {
	cfg := traefik_certauthz.CreateConfig()
	cfg.Regex = "^example\\.org$"

	testValidConfig(t, cfg, "", "403 Forbidden")
}

//
// TEST HELPERS
//

func testValidConfig(t *testing.T, cfg *traefik_certauthz.Config, cn string, expected string) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := traefik_certauthz.New(ctx, next, cfg, "certauthz")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	if cn != "" {
		cert := createCertificate(cn)
		req.TLS = createTLSConnectionState(cert)
	}

	handler.ServeHTTP(recorder, req)
	res := recorder.Result()

	if res.Status != expected {
		t.Errorf("expected status '%s', got '%s'", expected, res.Status)
	}
}

func createTLSConnectionState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
}

func createCertificate(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}
}
