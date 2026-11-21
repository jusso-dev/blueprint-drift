package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public Microsoft Graph REST API endpoint.
	DefaultBaseURL = "https://graph.microsoft.com"

	defaultMaxRetries = 4
	defaultBaseDelay  = 500 * time.Millisecond
	defaultMaxPages   = 100
	maxResponseBytes  = 32 << 20 // 32 MiB safety cap per page
)

var (
	// ErrWriteMethodBlocked is returned whenever a non-GET HTTP request reaches ReadOnlyTransport.
	ErrWriteMethodBlocked = errors.New("write or non-GET HTTP method is blocked by read-only Graph transport")
	// ErrUntrustedHost is returned when a request or @odata.nextLink targets a host outside the allow-list.
	ErrUntrustedHost = errors.New("request host is not in the allowed Graph host list")
)

// Response captures the exact read-only Graph query, status and reproducible digest.
type Response struct {
	Query      string `json:"query"`
	StatusCode int    `json:"status_code"`
	RawBody    []byte `json:"-"`
	SHA256     string `json:"sha256"`
	Pages      int    `json:"pages"`
}

// Client is the read-only Microsoft Graph client contract shared by direct,
// junction and fixture backends.
type Client interface {
	Get(ctx context.Context, version, endpoint string) (*Response, error)
	GetAllPages(ctx context.Context, version, endpoint string) (*Response, error)
}

// ReadOnlyTransport wraps an http.RoundTripper and blocks any non-GET request
// or any host not present in AllowedHosts.
type ReadOnlyTransport struct {
	Base         http.RoundTripper
	AllowedHosts map[string]bool
}

// RoundTrip enforces GET-only and host allow-list checks before forwarding.
func (t *ReadOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("nil HTTP request")
	}
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("%w: %s %s", ErrWriteMethodBlocked, req.Method, req.URL.String())
	}
	if len(t.AllowedHosts) > 0 {
		host := strings.ToLower(req.URL.Host)
		if !t.AllowedHosts[host] {
			return nil, fmt.Errorf("%w: %s", ErrUntrustedHost, host)
		}
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// DirectClient calls Microsoft Graph directly over HTTPS using GET-only requests
// with throttling retries and @odata.nextLink pagination.
type DirectClient struct {
	BaseURL    string
	Tokens     TokenProvider
	HTTPClient *http.Client
	MaxRetries int
	BaseDelay  time.Duration
	MaxPages   int
	UserAgent  string
	Sleep      func(ctx context.Context, d time.Duration) error
}

// DirectOption customises DirectClient construction.
type DirectOption func(*DirectClient)

// WithBaseURL overrides the Microsoft Graph base URL (for example sovereign clouds or test servers).
func WithBaseURL(baseURL string) DirectOption {
	return func(c *DirectClient) {
		c.BaseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithMaxRetries sets the maximum number of retry attempts on 429/503/504 responses.
func WithMaxRetries(n int) DirectOption {
	return func(c *DirectClient) {
		c.MaxRetries = n
	}
}

// WithBaseDelay sets the initial backoff delay when Retry-After is absent.
func WithBaseDelay(d time.Duration) DirectOption {
	return func(c *DirectClient) {
		c.BaseDelay = d
	}
}

// WithSleep overrides the backoff wait function (useful in deterministic tests).
func WithSleep(fn func(ctx context.Context, d time.Duration) error) DirectOption {
	return func(c *DirectClient) {
		c.Sleep = fn
	}
}

// WithTransport sets the underlying RoundTripper wrapped by ReadOnlyTransport.
func WithTransport(rt http.RoundTripper) DirectOption {
	return func(c *DirectClient) {
		if c.HTTPClient == nil {
			c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
		}
		if rot, ok := c.HTTPClient.Transport.(*ReadOnlyTransport); ok {
			rot.Base = rt
		} else {
			c.HTTPClient.Transport = &ReadOnlyTransport{Base: rt}
		}
	}
}

// NewDirectClient constructs a read-only Microsoft Graph DirectClient.
func NewDirectClient(tokens TokenProvider, opts ...DirectOption) (*DirectClient, error) {
	if tokens == nil {
		return nil, errors.New("token provider is required")
	}
	c := &DirectClient{
		BaseURL:    DefaultBaseURL,
		Tokens:     tokens,
		MaxRetries: defaultMaxRetries,
		BaseDelay:  defaultBaseDelay,
		MaxPages:   defaultMaxPages,
		UserAgent:  "blueprint-drift/read-only",
		Sleep:      sleepWithContext,
	}
	for _, opt := range opts {
		opt(c)
	}

	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Graph base URL %q", c.BaseURL)
	}

	allowed := map[string]bool{strings.ToLower(parsed.Host): true}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &ReadOnlyTransport{
				Base:         http.DefaultTransport,
				AllowedHosts: allowed,
			},
		}
	} else {
		switch existing := c.HTTPClient.Transport.(type) {
		case *ReadOnlyTransport:
			existing.AllowedHosts = allowed
		default:
			c.HTTPClient.Transport = &ReadOnlyTransport{
				Base:         existing,
				AllowedHosts: allowed,
			}
		}
	}
	return c, nil
}

// Get executes a single read-only GET call to /{version}{endpoint}.
func (c *DirectClient) Get(ctx context.Context, version, endpoint string) (*Response, error) {
	if version != "v1.0" && version != "beta" {
		return nil, fmt.Errorf("unsupported Graph version %q (expected v1.0 or beta)", version)
	}
	if !strings.HasPrefix(endpoint, "/") {
		return nil, fmt.Errorf("Graph endpoint must start with '/', got %q", endpoint)
	}
	fullURL := fmt.Sprintf("%s/%s%s", c.BaseURL, version, endpoint)
	body, status, err := c.doGetWithRetry(ctx, fullURL)
	if err != nil {
		return nil, err
	}
	canonical := CanonicalJSON(body)
	return &Response{
		Query:      fmt.Sprintf("GET /%s%s", version, endpoint),
		StatusCode: status,
		RawBody:    canonical,
		SHA256:     DigestSHA256(canonical),
		Pages:      1,
	}, nil
}

// GetAllPages follows @odata.nextLink until all pages are collected and merges
// their "value" arrays into a single canonical JSON object.
func (c *DirectClient) GetAllPages(ctx context.Context, version, endpoint string) (*Response, error) {
	if version != "v1.0" && version != "beta" {
		return nil, fmt.Errorf("unsupported Graph version %q (expected v1.0 or beta)", version)
	}
	if !strings.HasPrefix(endpoint, "/") {
		return nil, fmt.Errorf("Graph endpoint must start with '/', got %q", endpoint)
	}

	nextURL := fmt.Sprintf("%s/%s%s", c.BaseURL, version, endpoint)
	var (
		allValues  []json.RawMessage
		firstBody  []byte
		lastStatus int
		pages      int
		odataCtx   string
	)

	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}

	for nextURL != "" {
		pages++
		if pages > maxPages {
			return nil, fmt.Errorf("exceeded maximum pagination depth (%d pages) for %s", maxPages, endpoint)
		}

		body, status, err := c.doGetWithRetry(ctx, nextURL)
		if err != nil {
			return nil, err
		}
		lastStatus = status
		if pages == 1 {
			firstBody = body
		}

		var envelope struct {
			Context  string            `json:"@odata.context"`
			NextLink string            `json:"@odata.nextLink"`
			Value    []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			// Non-collection or non-JSON payload: return first page as-is.
			canonical := CanonicalJSON(body)
			return &Response{
				Query:      fmt.Sprintf("GET /%s%s", version, endpoint),
				StatusCode: lastStatus,
				RawBody:    canonical,
				SHA256:     DigestSHA256(canonical),
				Pages:      pages,
			}, nil
		}

		if pages == 1 {
			odataCtx = envelope.Context
		}
		if envelope.Value != nil {
			allValues = append(allValues, envelope.Value...)
		} else if pages == 1 && envelope.NextLink == "" {
			// Single entity response (not a collection with "value").
			canonical := CanonicalJSON(firstBody)
			return &Response{
				Query:      fmt.Sprintf("GET /%s%s", version, endpoint),
				StatusCode: lastStatus,
				RawBody:    canonical,
				SHA256:     DigestSHA256(canonical),
				Pages:      1,
			}, nil
		}

		if envelope.NextLink != "" {
			if err := c.validateNextLink(envelope.NextLink); err != nil {
				return nil, err
			}
		}
		nextURL = envelope.NextLink
	}

	merged := map[string]any{
		"value": allValues,
	}
	if odataCtx != "" {
		merged["@odata.context"] = odataCtx
	}
	mergedBytes, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal paginated Graph response: %w", err)
	}
	canonical := CanonicalJSON(mergedBytes)
	return &Response{
		Query:      fmt.Sprintf("GET /%s%s", version, endpoint),
		StatusCode: lastStatus,
		RawBody:    canonical,
		SHA256:     DigestSHA256(canonical),
		Pages:      pages,
	}, nil
}

func (c *DirectClient) validateNextLink(raw string) error {
	baseParsed, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	nextParsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid @odata.nextLink %q: %w", raw, err)
	}
	if !strings.EqualFold(nextParsed.Host, baseParsed.Host) {
		return fmt.Errorf("%w: @odata.nextLink host %q does not match %q", ErrUntrustedHost, nextParsed.Host, baseParsed.Host)
	}
	if nextParsed.Scheme != baseParsed.Scheme {
		return fmt.Errorf("%w: @odata.nextLink scheme %q does not match %q", ErrUntrustedHost, nextParsed.Scheme, baseParsed.Scheme)
	}
	return nil
}

func (c *DirectClient) doGetWithRetry(ctx context.Context, rawURL string) ([]byte, int, error) {
	maxRetries := c.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	baseDelay := c.BaseDelay
	if baseDelay <= 0 {
		baseDelay = defaultBaseDelay
	}
	sleepFn := c.Sleep
	if sleepFn == nil {
		sleepFn = sleepWithContext
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		token, err := c.Tokens.Token(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("acquire access token: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("build GET request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("ConsistencyLevel", "eventual")
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrWriteMethodBlocked) || errors.Is(err, ErrUntrustedHost) {
				return nil, 0, err
			}
			if attempt < maxRetries {
				if sleepErr := sleepFn(ctx, backoffDelay(baseDelay, attempt)); sleepErr != nil {
					return nil, 0, sleepErr
				}
				continue
			}
			return nil, 0, fmt.Errorf("GET %s failed: %w", rawURL, lastErr)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("read response body: %w", readErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, resp.StatusCode, nil
		}

		if isRetryableStatus(resp.StatusCode) && attempt < maxRetries {
			delay := parseRetryAfter(resp.Header.Get("Retry-After"), backoffDelay(baseDelay, attempt))
			if sleepErr := sleepFn(ctx, delay); sleepErr != nil {
				return nil, resp.StatusCode, sleepErr
			}
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
			continue
		}

		return nil, resp.StatusCode, fmt.Errorf("Graph GET %s returned HTTP %d: %s", rawURL, resp.StatusCode, truncate(string(body), 300))
	}

	return nil, 0, fmt.Errorf("Graph GET %s failed after %d retries: %w", rawURL, maxRetries, lastErr)
}

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

func backoffDelay(base time.Duration, attempt int) time.Duration {
	delay := base << attempt
	if delay > 60*time.Second {
		return 60 * time.Second
	}
	return delay
}

func parseRetryAfter(header string, fallback time.Duration) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return fallback
	}
	if secs, err := strconv.Atoi(header); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return fallback
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// CanonicalJSON re-serialises valid JSON with deterministically sorted object
// keys so SHA-256 hashes are reproducible across runs and platforms.
func CanonicalJSON(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// DigestSHA256 computes the lowercase hex SHA-256 digest of b.
func DigestSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
