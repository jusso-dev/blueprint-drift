package graph

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadOnlyTransportBlocksWriteMethods(t *testing.T) {
	rt := &ReadOnlyTransport{
		AllowedHosts: map[string]bool{"graph.microsoft.com": true},
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, err := http.NewRequest(method, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		_, err = rt.RoundTrip(req)
		if !errors.Is(err, ErrWriteMethodBlocked) {
			t.Fatalf("expected ErrWriteMethodBlocked for %s, got %v", method, err)
		}
	}
}

func TestReadOnlyTransportBlocksUntrustedHost(t *testing.T) {
	rt := &ReadOnlyTransport{
		AllowedHosts: map[string]bool{"graph.microsoft.com": true},
	}
	req, err := http.NewRequest(http.MethodGet, "https://evil.example.com/v1.0/policies", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = rt.RoundTrip(req)
	if !errors.Is(err, ErrUntrustedHost) {
		t.Fatalf("expected ErrUntrustedHost, got %v", err)
	}
}

func TestDirectClientRetriesThrottlingWithRetryAfter(t *testing.T) {
	var calls atomic.Int32
	var slept []time.Duration

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected HTTP method %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header %q", r.Header.Get("Authorization"))
		}
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests"}}`))
			return
		}
		if n == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"ServiceUnavailable"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"b":2,"a":1}`))
	}))
	defer srv.Close()

	client, err := NewDirectClient(
		&StaticTokenProvider{AccessToken: "test-token"},
		WithBaseURL(srv.URL),
		WithBaseDelay(10*time.Millisecond),
		WithSleep(func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewDirectClient: %v", err)
	}

	resp, err := client.Get(context.Background(), "v1.0", "/policies/identitySecurityDefaultsEnforcementPolicy")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls.Load())
	}
	if len(slept) != 2 || slept[0] != 2*time.Second {
		t.Fatalf("unexpected sleep delays: %v", slept)
	}
	// Canonical JSON sorts keys alphabetically ("a" before "b").
	if string(resp.RawBody) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical body: %s", string(resp.RawBody))
	}
	if resp.SHA256 != DigestSHA256([]byte(`{"a":1,"b":2}`)) {
		t.Fatalf("unexpected SHA256 digest: %s", resp.SHA256)
	}
}

func TestDirectClientPaginationAndUntrustedNextLink(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RequestURI() {
		case "/v1.0/identity/conditionalAccess/policies":
			_, _ = fmt.Fprintf(w, `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#policies","value":[{"id":"1"}],"@odata.nextLink":"%s/v1.0/identity/conditionalAccess/policies?page=2"}`, srvURL)
		case "/v1.0/identity/conditionalAccess/policies?page=2":
			_, _ = w.Write([]byte(`{"value":[{"id":"2"}]}`))
		case "/v1.0/evil":
			_, _ = w.Write([]byte(`{"value":[{"id":"1"}],"@odata.nextLink":"https://attacker.example.com/steal-token"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	client, err := NewDirectClient(&StaticTokenProvider{AccessToken: "tok"}, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("NewDirectClient: %v", err)
	}

	resp, err := client.GetAllPages(context.Background(), "v1.0", "/identity/conditionalAccess/policies")
	if err != nil {
		t.Fatalf("GetAllPages failed: %v", err)
	}
	if resp.Pages != 2 {
		t.Fatalf("expected 2 pages, got %d", resp.Pages)
	}
	var parsed struct {
		Value []map[string]string `json:"value"`
	}
	if err := json.Unmarshal(resp.RawBody, &parsed); err != nil {
		t.Fatalf("unmarshal merged body: %v", err)
	}
	if len(parsed.Value) != 2 || parsed.Value[0]["id"] != "1" || parsed.Value[1]["id"] != "2" {
		t.Fatalf("unexpected merged values: %+v", parsed.Value)
	}

	_, err = client.GetAllPages(context.Background(), "v1.0", "/evil")
	if !errors.Is(err, ErrUntrustedHost) {
		t.Fatalf("expected ErrUntrustedHost for cross-host nextLink, got %v", err)
	}
}

func TestCertificateAuthProviderSignsValidJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "blueprint-drift-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assertion := r.FormValue("client_assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3-part JWT, got %d parts", len(parts))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Errorf("decode signature: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("invalid JWT signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"app-only-token","expires_in":3600}`))
	}))
	defer srv.Close()

	provider, err := NewCertificateAuthProvider(CertificateAuthConfig{
		TenantID:      "00000000-0000-0000-0000-000000000000",
		ClientID:      "11111111-1111-1111-1111-111111111111",
		Certificate:   cert,
		PrivateKey:    priv,
		AuthorityBase: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewCertificateAuthProvider: %v", err)
	}

	tok1, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 1 failed: %v", err)
	}
	tok2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Token 2 failed: %v", err)
	}
	if tok1 != "app-only-token" || tok2 != "app-only-token" {
		t.Fatalf("unexpected tokens: %q, %q", tok1, tok2)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("expected cached token (1 HTTP call), got %d", tokenCalls.Load())
	}
}

func TestDeviceCodeAuthProviderFlow(t *testing.T) {
	var polls atomic.Int32
	var prompted DeviceCodePrompt

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/devicecode"):
			_, _ = w.Write([]byte(`{"user_code":"ABCD-EFGH","device_code":"dev-123","verification_uri":"https://microsoft.com/devicelogin","expires_in":600,"interval":1,"message":"Sign in"}`))
		case strings.HasSuffix(r.URL.Path, "/token"):
			n := polls.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			if n == 2 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"delegated-token","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	provider, err := NewDeviceCodeAuthProvider(DeviceCodeAuthConfig{
		TenantID:      "00000000-0000-0000-0000-000000000000",
		ClientID:      "11111111-1111-1111-1111-111111111111",
		Scopes:        []string{"https://graph.microsoft.com/Policy.Read.All"},
		AuthorityBase: srv.URL,
		OnPrompt:      func(p DeviceCodePrompt) { prompted = p },
		Sleep:         func(_ context.Context, _ time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewDeviceCodeAuthProvider: %v", err)
	}

	tok, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}
	if tok != "delegated-token" {
		t.Fatalf("expected delegated-token, got %q", tok)
	}
	if prompted.UserCode != "ABCD-EFGH" {
		t.Fatalf("expected prompt callback with user_code, got %+v", prompted)
	}
	if polls.Load() != 3 {
		t.Fatalf("expected 3 token polls, got %d", polls.Load())
	}

	// Verify write scopes are rejected at construction time.
	_, err = NewDeviceCodeAuthProvider(DeviceCodeAuthConfig{
		TenantID: "00000000-0000-0000-0000-000000000000",
		ClientID: "11111111-1111-1111-1111-111111111111",
		Scopes:   []string{"https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess"},
	})
	if err == nil {
		t.Fatal("expected error for write scope, got nil")
	}
}

func TestJunctionClientReadOnlyAndWriteRejection(t *testing.T) {
	jc := NewJunctionClient("junction", "prod-ro", map[string]string{
		"/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": "graph.policies.identity_security_defaults_enforcement_policy.get",
		"/v1.0/policies/badWrite":                                  "graph.policies.conditional_access.delete",
	})
	jc.Runner = func(_ context.Context, binary string, args ...string) ([]byte, error) {
		if binary != "junction" {
			t.Fatalf("unexpected binary %q", binary)
		}
		return []byte(`{"isEnabled":false}`), nil
	}

	resp, err := jc.Get(context.Background(), "v1.0", "/policies/identitySecurityDefaultsEnforcementPolicy")
	if err != nil {
		t.Fatalf("Junction Get failed: %v", err)
	}
	if string(resp.RawBody) != `{"isEnabled":false}` {
		t.Fatalf("unexpected body: %s", string(resp.RawBody))
	}

	_, err = jc.Get(context.Background(), "v1.0", "/policies/badWrite")
	if !errors.Is(err, ErrWriteMethodBlocked) {
		t.Fatalf("expected ErrWriteMethodBlocked for delete op, got %v", err)
	}
}

func TestFixtureClientLoadDir(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "v1.0", "policies", "authorizationPolicy.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"blockMsolPowerShell":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	fc, err := LoadFixtureDir(tmp)
	if err != nil {
		t.Fatalf("LoadFixtureDir: %v", err)
	}
	resp, err := fc.Get(context.Background(), "v1.0", "/policies/authorizationPolicy")
	if err != nil {
		t.Fatalf("FixtureClient.Get: %v", err)
	}
	if string(resp.RawBody) != `{"blockMsolPowerShell":true}` {
		t.Fatalf("unexpected fixture response: %s", string(resp.RawBody))
	}
}
