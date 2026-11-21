package blueprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONSchemaIsValidJSON(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "blueprint", "schema", "settings.schema.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse JSON Schema: %v", err)
	}
	if parsed["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected $schema: %v", parsed["$schema"])
	}
}

func TestLoadRepoBlueprintSettings(t *testing.T) {
	settingsDir := filepath.Join("..", "..", "blueprint", "settings")
	catalogs, err := LoadDir(settingsDir)
	if err != nil {
		t.Fatalf("LoadDir(%s) failed: %v", settingsDir, err)
	}
	total := 0
	for _, c := range catalogs {
		total += len(c.Settings)
	}
	if total == 0 {
		t.Fatal("expected at least one validated Blueprint setting")
	}
}

func TestValidateSettingRejectsWriteMethodAndPermission(t *testing.T) {
	base := Setting{
		ID:          "ENTRA-TEST-001",
		Section:     "Entra ID / Test",
		Title:       "Test setting",
		Description: "Test description.",
		Severity:    "high",
		Expected:    Expected{Operator: "equals", Path: "isEnabled", Value: false},
		APISource: APISource{
			Kind:        "graph",
			Version:     "v1.0",
			Method:      "POST",
			Endpoint:    "/policies/test",
			Permissions: []string{"Policy.Read.All"},
		},
		ISMControls: []string{"ISM-1507"},
		References:  []string{"https://blueprint.asd.gov.au/"},
	}

	if err := ValidateSetting(&base); err == nil || !strings.Contains(err.Error(), "GET") {
		t.Fatalf("expected GET-only error, got %v", err)
	}

	base.APISource.Method = "GET"
	base.APISource.Permissions = []string{"Policy.ReadWrite.ConditionalAccess"}
	if err := ValidateSetting(&base); err == nil || !strings.Contains(err.Error(), "write permission") {
		t.Fatalf("expected write permission error, got %v", err)
	}
}

func TestValidateSettingRejectsManualWithoutReason(t *testing.T) {
	s := Setting{
		ID:          "ENTRA-TEST-002",
		Section:     "Entra ID / Test",
		Title:       "Manual setting",
		Description: "Manual check.",
		Severity:    "medium",
		Expected:    Expected{Operator: "manual"},
		APISource:   APISource{Kind: "manual"},
		ISMControls: []string{"ISM-0445"},
		References:  []string{"https://blueprint.asd.gov.au/"},
	}
	if err := ValidateSetting(&s); err == nil || !strings.Contains(err.Error(), "manual_reason") {
		t.Fatalf("expected manual_reason error, got %v", err)
	}
}
