package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

type countingClient struct {
	inner graph.Client
	calls map[string]int
}

func (c *countingClient) Get(ctx context.Context, version, endpoint string) (*graph.Response, error) {
	c.calls[version+":"+endpoint]++
	return c.inner.Get(ctx, version, endpoint)
}

func (c *countingClient) GetAllPages(ctx context.Context, version, endpoint string) (*graph.Response, error) {
	c.calls[version+":"+endpoint]++
	return c.inner.GetAllPages(ctx, version, endpoint)
}

func TestRunnerCachesEndpointsAndEvaluatesDeclarativeAndManual(t *testing.T) {
	fx := graph.NewFixtureClient(map[string][]byte{
		"/v1.0/policies/authorizationPolicy": []byte(`{
			"defaultUserRolePermissions": {
				"allowedToCreateApps": false,
				"allowedToCreateTenants": true
			}
		}`),
	})
	cc := &countingClient{inner: fx, calls: make(map[string]int)}

	cat := &blueprint.Catalog{
		SchemaVersion:    "1.0",
		BlueprintVersion: "v1.4.0",
		Domain:           "entra-id",
		Settings: []blueprint.Setting{
			{
				ID:          "ENTRA-USER-001",
				Section:     "Entra ID / User settings",
				Title:       "Disable user app registration",
				Description: "Non-admin users must not register applications.",
				Severity:    "high",
				Expected:    blueprint.Expected{Operator: "equals", Path: "defaultUserRolePermissions.allowedToCreateApps", Value: false},
				APISource:   blueprint.APISource{Kind: "graph", Version: "v1.0", Method: "GET", Endpoint: "/policies/authorizationPolicy", Permissions: []string{"Policy.Read.All"}},
				ISMControls: []string{"ISM-1507"},
				References:  []string{"https://blueprint.asd.gov.au/"},
			},
			{
				ID:          "ENTRA-USER-002",
				Section:     "Entra ID / User settings",
				Title:       "Restrict tenant creation",
				Description: "Non-admin users must not create tenants.",
				Severity:    "medium",
				Expected:    blueprint.Expected{Operator: "equals", Path: "defaultUserRolePermissions.allowedToCreateTenants", Value: false},
				APISource:   blueprint.APISource{Kind: "graph", Version: "v1.0", Method: "GET", Endpoint: "/policies/authorizationPolicy", Permissions: []string{"Policy.Read.All"}},
				ISMControls: []string{"ISM-1507"},
				References:  []string{"https://blueprint.asd.gov.au/"},
			},
			{
				ID:          "ENTRA-BG-001",
				Section:     "Entra ID / Break-glass",
				Title:       "Emergency access governance",
				Description: "Manual governance check.",
				Severity:    "high",
				Expected:    blueprint.Expected{Operator: "manual"},
				APISource:   blueprint.APISource{Kind: "manual", ManualReason: "Operational vault check"},
				ISMControls: []string{"ISM-0445"},
				References:  []string{"https://blueprint.asd.gov.au/"},
			},
		},
	}

	fixedTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	runner := &Runner{
		Client:   cc,
		Registry: NewRegistry(),
		TenantID: "00000000-0000-0000-0000-000000000000",
		Now:      func() time.Time { return fixedTime },
	}

	res, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.Summary.Total != 3 || res.Summary.Pass != 1 || res.Summary.Fail != 1 || res.Summary.Manual != 1 {
		t.Fatalf("unexpected summary: %+v", res.Summary)
	}
	if cc.calls["v1.0:/policies/authorizationPolicy"] != 1 {
		t.Fatalf("expected endpoint cache hit (1 call), got %d", cc.calls["v1.0:/policies/authorizationPolicy"])
	}
	if res.Results[0].ResponseSHA256 == "" || res.Results[0].ResponseSHA256 != res.Results[1].ResponseSHA256 {
		t.Fatalf("expected matching non-empty SHA-256 digests for shared endpoint")
	}
}
