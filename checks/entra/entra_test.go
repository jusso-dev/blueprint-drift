package entra_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/checks/entra"
	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

func loadEntraCatalog(t *testing.T) *blueprint.Catalog {
	t.Helper()
	catPath := filepath.Join("..", "..", "blueprint", "settings", "entra-id.yaml")
	cat, err := blueprint.LoadFile(catPath)
	if err != nil {
		t.Fatalf("LoadFile(%s): %v", catPath, err)
	}
	return cat
}

func TestEntraChecksCompliantFixtures(t *testing.T) {
	cat := loadEntraCatalog(t)
	fx, err := graph.LoadFixtureDir(filepath.Join("testdata", "compliant"))
	if err != nil {
		t.Fatalf("LoadFixtureDir: %v", err)
	}

	reg := engine.NewRegistry()
	entra.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
		Now:      func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	}

	runRes, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}

	for _, r := range runRes.Results {
		if r.Status == engine.StatusFail || r.Status == engine.StatusError {
			t.Errorf("expected compliant setting %s to pass/manual, got %s: %s", r.SettingID, r.Status, r.Message)
		}
	}

	if runRes.Summary.Total != 32 || runRes.Summary.Pass != 30 || runRes.Summary.Manual != 2 || runRes.Summary.Fail != 0 || runRes.Summary.Error != 0 {
		t.Fatalf("unexpected compliant summary: %+v", runRes.Summary)
	}
}

func TestEntraChecksDriftedFixtures(t *testing.T) {
	cat := loadEntraCatalog(t)
	fx := graph.NewFixtureClient(map[string][]byte{
		"/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": []byte(`{"isEnabled":true}`),
		"/v1.0/organization": []byte(`{"value":[{"countryLetterCode":"US"}]}`),
		"/v1.0/policies/authorizationPolicy": []byte(`{
			"allowInvitesFrom": "everyone",
			"blockMsolPowerShell": false,
			"guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
			"defaultUserRolePermissions": {
				"allowedToCreateApps": true,
				"allowedToCreateSecurityGroups": true,
				"allowedToCreateTenants": true,
				"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
			}
		}`),
		"/beta/policies/authorizationPolicy":       []byte(`{"defaultUserRolePermissions":{"allowedToReadOtherUsers":true}}`),
		"/v1.0/policies/adminConsentRequestPolicy": []byte(`{"isEnabled":false}`),
		"/beta/policies/deviceRegistrationPolicy": []byte(`{
			"multiFactorAuthConfiguration": "unsupported",
			"userDeviceQuota": 50,
			"azureADJoin": {"allowedToJoin": {"@odata.type": "#microsoft.graph.noDeviceRegistrationMembership"}},
			"localAdminPassword": {"isEnabled": false}
		}`),
		"/v1.0/policies/crossTenantAccessPolicy/default": []byte(`{
			"b2bCollaborationInbound": {
				"usersAndGroups": {"accessType": "allowed"},
				"applications": {"accessType": "allowed"}
			}
		}`),
		"/beta/settings": []byte(`{"value":[]}`),
		"/v1.0/policies/authenticationMethodsPolicy": []byte(`{
			"systemCredentialPreferences": {"state": "disabled"},
			"authenticationMethodConfigurations": [
				{"id": "Fido2", "state": "disabled"},
				{"id": "Sms", "state": "enabled"},
				{"id": "Voice", "state": "enabled"},
				{"id": "Email", "state": "disabled"},
				{"id": "TemporaryAccessPass", "state": "enabled", "maximumLifetimeInMinutes": 1440}
			]
		}`),
		"/v1.0/identity/conditionalAccess/namedLocations": []byte(`{"value":[]}`),
		"/v1.0/identity/conditionalAccess/policies": []byte(`{
			"value": [
				{
					"id": "disabled-policy",
					"displayName": "BP - Block legacy auth (disabled)",
					"state": "disabled",
					"conditions": {
						"clientAppTypes": ["exchangeActiveSync", "other"],
						"users": {"includeUsers": ["All"]},
						"applications": {"includeApplications": ["All"]}
					},
					"grantControls": {"operator": "OR", "builtInControls": ["block"]}
				}
			]
		}`),
		"/v1.0/roleManagement/directory/roleAssignmentScheduleInstances": []byte(`{
			"value": [
				{"principalId": "p1", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "assignmentType": "Assigned", "endDateTime": null},
				{"principalId": "p2", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "assignmentType": "Assigned", "endDateTime": null},
				{"principalId": "p3", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "assignmentType": "Assigned", "endDateTime": null}
			]
		}`),
	})

	reg := engine.NewRegistry()
	entra.Register(reg)

	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
	}

	runRes, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}

	if runRes.Summary.Fail != 30 || runRes.Summary.Manual != 2 || runRes.Summary.Pass != 0 || runRes.Summary.Error != 0 {
		for _, r := range runRes.Results {
			if r.Status == engine.StatusPass || r.Status == engine.StatusError {
				t.Errorf("expected drifted setting %s to fail, got %s: %s", r.SettingID, r.Status, r.Message)
			}
		}
		t.Fatalf("unexpected drifted summary: %+v", runRes.Summary)
	}
}
