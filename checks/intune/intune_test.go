package intune_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/checks/intune"
	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

func loadIntuneCatalog(t *testing.T) *blueprint.Catalog {
	t.Helper()
	catPath := filepath.Join("..", "..", "blueprint", "settings", "intune.yaml")
	cat, err := blueprint.LoadFile(catPath)
	if err != nil {
		t.Fatalf("LoadFile(%s): %v", catPath, err)
	}
	return cat
}

func TestIntuneChecksCompliantFixtures(t *testing.T) {
	cat := loadIntuneCatalog(t)
	fx, err := graph.LoadFixtureDir(filepath.Join("testdata", "compliant"))
	if err != nil {
		t.Fatalf("LoadFixtureDir: %v", err)
	}

	reg := engine.NewRegistry()
	intune.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
		Now:      func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	}

	res, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}
	for _, r := range res.Results {
		if r.Status == engine.StatusFail || r.Status == engine.StatusError {
			t.Errorf("expected compliant setting %s to pass/manual, got %s: %s", r.SettingID, r.Status, r.Message)
		}
	}
	if res.Summary.Total != 16 || res.Summary.Pass != 14 || res.Summary.Manual != 2 || res.Summary.Fail != 0 || res.Summary.Error != 0 {
		t.Fatalf("unexpected compliant Intune summary: %+v", res.Summary)
	}
}

func TestIntuneChecksDriftedFixtures(t *testing.T) {
	cat := loadIntuneCatalog(t)
	fx := graph.NewFixtureClient(map[string][]byte{
		"/beta/deviceManagement/settings": []byte(`{
			"secureByDefault": false,
			"deviceComplianceCheckinThresholdDays": 90
		}`),
		"/v1.0/deviceManagement/deviceCompliancePolicies": []byte(`{
			"value": [
				{
					"@odata.type": "#microsoft.graph.windows10CompliancePolicy",
					"displayName": "Weak Windows Policy",
					"bitLockerEnabled": false,
					"secureBootEnabled": false,
					"codeIntegrityEnabled": false,
					"defenderEnabled": false,
					"rtpEnabled": false,
					"firewallEnabled": false,
					"antivirusRequired": false,
					"deviceThreatProtectionEnabled": false
				}
			]
		}`),
		"/beta/deviceManagement/configurationPolicies": []byte(`{"value":[]}`),
		"/v1.0/deviceManagement/deviceConfigurations":  []byte(`{"value":[]}`),
		"/beta/deviceManagement/intents":               []byte(`{"value":[{"id":"1","displayName":"Unassigned Baseline","isAssigned":false}]}`),
		"/v1.0/deviceAppManagement/iosManagedAppProtections": []byte(`{
			"value": [{"displayName":"Weak iOS MAM","pinRequired":false,"allowedOutboundDataTransferDestinations":"allApps","dataBackupBlocked":false}]
		}`),
		"/v1.0/deviceAppManagement/androidManagedAppProtections": []byte(`{"value":[]}`),
	})

	reg := engine.NewRegistry()
	intune.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
	}

	res, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}
	if res.Summary.Fail != 14 || res.Summary.Manual != 2 || res.Summary.Pass != 0 || res.Summary.Error != 0 {
		for _, r := range res.Results {
			if r.Status == engine.StatusPass || r.Status == engine.StatusError {
				t.Errorf("expected drifted setting %s to fail, got %s: %s", r.SettingID, r.Status, r.Message)
			}
		}
		t.Fatalf("unexpected drifted Intune summary: %+v", res.Summary)
	}
}
