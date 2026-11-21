package graph

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAuthorityBase is the public Microsoft Entra ID authority host.
	DefaultAuthorityBase = "https://login.microsoftonline.com"
	// DefaultGraphScope is the app-only default Microsoft Graph scope.
	DefaultGraphScope = "https://graph.microsoft.com/.default"
)

// TokenProvider returns a valid OAuth 2.0 bearer access token for Microsoft Graph.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// StaticTokenProvider returns a fixed bearer token (intended for testing or
// externally managed credentials).
type StaticTokenProvider struct {
	AccessToken string
}

// Token returns the configured static bearer token.
func (s *StaticTokenProvider) Token(_ context.Context) (string, error) {
	if strings.TrimSpace(s.AccessToken) == "" {
		return "", errors.New("static access token is empty")
	}
	return s.AccessToken, nil
}

// CertificateAuthConfig configures app-only certificate authentication using an
// RS256 signed JWT client assertion per Microsoft Entra ID OAuth 2.0 specs.
type CertificateAuthConfig struct {
	TenantID      string
	ClientID      string
	Certificate   *x509.Certificate
	PrivateKey    *rsa.PrivateKey
	Scope         string
	AuthorityBase string
	HTTPClient    *http.Client
	Now           func() time.Time
}

// CertificateAuthProvider acquires and caches app-only access tokens using an
// X.509 certificate and RSA private key.
type CertificateAuthProvider struct {
	cfg    CertificateAuthConfig
	mu     sync.Mutex
	token  string
	expiry time.Time
}

// LoadCertificateAndKey reads a PEM-encoded X.509 certificate and RSA private key from disk.
func LoadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse X.509 certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	if k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		return cert, k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not an RSA key")
	}
	return cert, rsaKey, nil
}

// NewCertificateAuthProvider validates cfg and creates a CertificateAuthProvider.
func NewCertificateAuthProvider(cfg CertificateAuthConfig) (*CertificateAuthProvider, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("tenant id is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("client id is required")
	}
	if cfg.Certificate == nil || cfg.PrivateKey == nil {
		return nil, errors.New("certificate and RSA private key are required")
	}
	if cfg.Scope == "" {
		cfg.Scope = DefaultGraphScope
	}
	if cfg.AuthorityBase == "" {
		cfg.AuthorityBase = DefaultAuthorityBase
	}
	cfg.AuthorityBase = strings.TrimRight(cfg.AuthorityBase, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &CertificateAuthProvider{cfg: cfg}, nil
}

// Token returns a cached token or exchanges a newly signed RS256 client assertion.
func (p *CertificateAuthProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.cfg.Now()
	if p.token != "" && now.Add(60*time.Second).Before(p.expiry) {
		return p.token, nil
	}

	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.cfg.AuthorityBase, url.PathEscape(p.cfg.TenantID))
	assertion, err := p.buildClientAssertion(tokenURL, now)
	if err != nil {
		return "", fmt.Errorf("build client assertion: %w", err)
	}

	form := url.Values{
		"client_id":             {p.cfg.ClientID},
		"scope":                 {p.cfg.Scope},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 250))
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", errors.New("token response did not contain access_token")
	}

	p.token = parsed.AccessToken
	ttl := time.Duration(parsed.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 55 * time.Minute
	}
	p.expiry = now.Add(ttl)
	return p.token, nil
}

func (p *CertificateAuthProvider) buildClientAssertion(audience string, now time.Time) (string, error) {
	thumbprint := sha1.Sum(p.cfg.Certificate.Raw)
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": base64.RawURLEncoding.EncodeToString(thumbprint[:]),
	}
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	claims := map[string]any{
		"aud": audience,
		"iss": p.cfg.ClientID,
		"sub": p.cfg.ClientID,
		"jti": base64.RawURLEncoding.EncodeToString(jtiBytes),
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.cfg.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// DeviceCodePrompt delivers the interactive device code verification message to the operator.
type DeviceCodePrompt struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// DeviceCodeAuthConfig configures delegated OAuth 2.0 device code authentication.
type DeviceCodeAuthConfig struct {
	TenantID      string
	ClientID      string
	Scopes        []string
	AuthorityBase string
	HTTPClient    *http.Client
	OnPrompt      func(DeviceCodePrompt)
	Sleep         func(ctx context.Context, d time.Duration) error
	Now           func() time.Time
}

// DeviceCodeAuthProvider acquires delegated read-only Graph tokens via OAuth 2.0 device code flow.
type DeviceCodeAuthProvider struct {
	cfg    DeviceCodeAuthConfig
	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewDeviceCodeAuthProvider validates cfg and returns a DeviceCodeAuthProvider.
func NewDeviceCodeAuthProvider(cfg DeviceCodeAuthConfig) (*DeviceCodeAuthProvider, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("tenant id is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("client id is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"https://graph.microsoft.com/Policy.Read.All", "https://graph.microsoft.com/Organization.Read.All"}
	}
	for _, s := range cfg.Scopes {
		if strings.Contains(s, "Write") || strings.Contains(s, "ReadWrite") {
			return nil, fmt.Errorf("write scope %q is not permitted in read-only blueprint-drift", s)
		}
	}
	if cfg.AuthorityBase == "" {
		cfg.AuthorityBase = DefaultAuthorityBase
	}
	cfg.AuthorityBase = strings.TrimRight(cfg.AuthorityBase, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepWithContext
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &DeviceCodeAuthProvider{cfg: cfg}, nil
}

// Token runs the device code flow (or returns a cached token if still valid).
func (p *DeviceCodeAuthProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.cfg.Now()
	if p.token != "" && now.Add(60*time.Second).Before(p.expiry) {
		return p.token, nil
	}

	deviceURL := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", p.cfg.AuthorityBase, url.PathEscape(p.cfg.TenantID))
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.cfg.AuthorityBase, url.PathEscape(p.cfg.TenantID))

	form := url.Values{
		"client_id": {p.cfg.ClientID},
		"scope":     {strings.Join(p.cfg.Scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("device code request failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if readErr != nil {
		return "", readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("device code endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 250))
	}

	var prompt DeviceCodePrompt
	if err := json.Unmarshal(body, &prompt); err != nil {
		return "", fmt.Errorf("decode device code response: %w", err)
	}
	if prompt.DeviceCode == "" {
		return "", errors.New("device code response missing device_code")
	}
	if p.cfg.OnPrompt != nil {
		p.cfg.OnPrompt(prompt)
	}

	interval := time.Duration(prompt.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := now.Add(time.Duration(prompt.ExpiresIn) * time.Second)
	if prompt.ExpiresIn <= 0 {
		deadline = now.Add(15 * time.Minute)
	}

	for {
		if err := p.cfg.Sleep(ctx, interval); err != nil {
			return "", err
		}
		if p.cfg.Now().After(deadline) {
			return "", errors.New("device code expired before sign-in completed")
		}

		pollForm := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {p.cfg.ClientID},
			"device_code": {prompt.DeviceCode},
		}
		pollReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(pollForm.Encode()))
		if err != nil {
			return "", err
		}
		pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		pollResp, err := p.cfg.HTTPClient.Do(pollReq)
		if err != nil {
			return "", fmt.Errorf("device code token poll failed: %w", err)
		}
		pollBody, pollReadErr := io.ReadAll(io.LimitReader(pollResp.Body, 1<<20))
		_ = pollResp.Body.Close()
		if pollReadErr != nil {
			return "", pollReadErr
		}

		var result struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			Error       string `json:"error"`
			ErrorDesc   string `json:"error_description"`
		}
		if err := json.Unmarshal(pollBody, &result); err != nil {
			return "", fmt.Errorf("decode token poll response: %w", err)
		}

		if pollResp.StatusCode >= 200 && pollResp.StatusCode < 300 && result.AccessToken != "" {
			p.token = result.AccessToken
			ttl := time.Duration(result.ExpiresIn) * time.Second
			if ttl <= 0 {
				ttl = 55 * time.Minute
			}
			p.expiry = p.cfg.Now().Add(ttl)
			return p.token, nil
		}

		switch result.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "authorization_declined":
			return "", errors.New("device code sign-in was declined by the user")
		case "expired_token":
			return "", errors.New("device code expired")
		default:
			return "", fmt.Errorf("device code token error %q: %s", result.Error, result.ErrorDesc)
		}
	}
}
