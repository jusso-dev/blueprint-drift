package m365_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/checks/m365"
	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

func loadM365Catalogs(t *testing.T) []*blueprint.Catalog {
	t.Helper()
	files := []string{
		"exchange-online.yaml",
		"sharepoint-online.yaml",
		"teams.yaml",
		"defender.yaml",
	}
	var catalogs []*blueprint.Catalog
	for _, f := range files {
		p := filepath.Join("..", "..", "blueprint", "settings", f)
		cat, err := blueprint.LoadFile(p)
		if err != nil {
			t.Fatalf("LoadFile(%s): %v", p, err)
		}
		catalogs = append(catalogs, cat)
	}
	return catalogs
}

func TestM365AndDefenderCompliantFixtures(t *testing.T) {
	catalogs := loadM365Catalogs(t)
	fx, err := graph.LoadFixtureDir(filepath.Join("testdata", "compliant"))
	if err != nil {
		t.Fatalf("LoadFixtureDir: %v", err)
	}

	reg := engine.NewRegistry()
	m365.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
		Now:      func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	}

	res, err := runner.Run(context.Background(), catalogs)
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}

	for _, r := range res.Results {
		if r.Status == engine.StatusFail || r.Status == engine.StatusError {
			t.Errorf("expected compliant setting %s to pass/manual, got %s: %s", r.SettingID, r.Status, r.Message)
		}
	}
	if res.Summary.Total != 35 || res.Summary.Pass != 11 || res.Summary.Manual != 24 || res.Summary.Fail != 0 || res.Summary.Error != 0 {
		t.Fatalf("unexpected compliant M365/Defender summary: %+v", res.Summary)
	}
}

func TestM365AndDefenderDriftedFixtures(t *testing.T) {
	catalogs := loadM365Catalogs(t)
	fx := graph.NewFixtureClient(map[string][]byte{
		"/v1.0/domains": []byte(`{"value":[{"id":"example.onmicrosoft.com","isVerified":true}]}`),
		"/v1.0/admin/sharepoint/settings": []byte(`{
			"sharingCapability": "externalUserAndGuestSharing",
			"sharingDomainRestrictionMode": "none",
			"sharingAllowedDomainList": [],
			"isResharingByExternalUsersEnabled": true,
			"isUnmanagedSyncAppForTenantRestricted": false,
			"idleSessionSignOut": {"isEnabled": false}
		}`),
		"/v1.0/security/secureScores": []byte(`{"value":[]}`),
		"/v1.0/security/secureScoreControlProfiles": []byte(`{
			"value": [{"id":"AdminMFAV2","controlStateUpdates":[{"state":"Ignored","comment":""}]}]
		}`),
		"/beta/deviceManagement/mobileThreatDefenseConnectors": []byte(`{"value":[{"id":"windowsDefenderATP","partnerState":"unavailable","windowsEnabled":false}]}`),
		"/beta/deviceManagement/configurationPolicies":         []byte(`{"value":[]}`),
		"/v1.0/security/incidents":                             []byte(`{}`),
	})

	reg := engine.NewRegistry()
	m365.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
	}

	res, err := runner.Run(context.Background(), catalogs)
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}

	if res.Summary.Fail != 11 || res.Summary.Manual != 24 || res.Summary.Pass != 0 || res.Summary.Error != 0 {
		for _, r := range res.Results {
			if r.Status == engine.StatusPass || r.Status == engine.StatusError {
				t.Errorf("expected drifted setting %s to fail, got %s: %s", r.SettingID, r.Status, r.Message)
			}
		}
		t.Fatalf("unexpected drifted M365/Defender summary: %+v", res.Summary)
	}
}
