package graph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FixtureClient serves deterministic Microsoft Graph JSON responses from memory
// or a local directory for offline testing and sample evidence pack generation.
type FixtureClient struct {
	Responses map[string][]byte
}

// NewFixtureClient creates a FixtureClient from an in-memory map keyed by
// "/v1.0/..." or "/beta/...".
func NewFixtureClient(responses map[string][]byte) *FixtureClient {
	copied := make(map[string][]byte, len(responses))
	for k, v := range responses {
		copied[k] = append([]byte(nil), v...)
	}
	return &FixtureClient{Responses: copied}
}

// LoadFixtureDir loads JSON fixture files from dir. Files are mapped using their
// relative path without the .json extension prefixed with "/" (for example
// v1.0/policies/authorizationPolicy.json -> /v1.0/policies/authorizationPolicy).
func LoadFixtureDir(dir string) (*FixtureClient, error) {
	responses := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || strings.ToLower(filepath.Ext(path)) != ".json" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		key := "/" + strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		responses[key] = raw
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load fixtures from %s: %w", dir, err)
	}
	return &FixtureClient{Responses: responses}, nil
}

// Get returns the fixture payload for /{version}{endpoint}.
func (f *FixtureClient) Get(_ context.Context, version, endpoint string) (*Response, error) {
	key := fmt.Sprintf("/%s%s", version, endpoint)
	raw, ok := f.Responses[key]
	if !ok {
		// Fall back to path without query string when query parameters are present.
		if idx := strings.Index(key, "?"); idx != -1 {
			raw, ok = f.Responses[key[:idx]]
		}
	}
	if !ok {
		return nil, fmt.Errorf("fixture not found for %s", key)
	}
	canonical := CanonicalJSON(raw)
	return &Response{
		Query:      fmt.Sprintf("GET %s", key),
		StatusCode: 200,
		RawBody:    canonical,
		SHA256:     DigestSHA256(canonical),
		Pages:      1,
	}, nil
}

// GetAllPages returns the fixture payload for /{version}{endpoint}.
func (f *FixtureClient) GetAllPages(ctx context.Context, version, endpoint string) (*Response, error) {
	return f.Get(ctx, version, endpoint)
}
