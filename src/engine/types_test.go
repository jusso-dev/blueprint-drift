package engine

import "testing"

func TestComputeSummary(t *testing.T) {
	results := []CheckResult{
		{SettingID: "ENTRA-PROP-001", Status: StatusPass},
		{SettingID: "ENTRA-USER-001", Status: StatusFail},
		{SettingID: "ENTRA-BG-001", Status: StatusManual},
		{SettingID: "ENTRA-CA-001", Status: StatusError},
		{SettingID: "ENTRA-CA-002", Status: StatusPass},
	}

	got := ComputeSummary(results)
	if got.Total != 5 || got.Pass != 2 || got.Fail != 1 || got.Manual != 1 || got.Error != 1 {
		t.Fatalf("unexpected summary: %+v", got)
	}
}

func TestValidateStatus(t *testing.T) {
	for _, st := range []Status{StatusPass, StatusFail, StatusManual, StatusError} {
		if err := ValidateStatus(st); err != nil {
			t.Fatalf("expected valid status %q, got error: %v", st, err)
		}
	}
	if err := ValidateStatus(Status("unknown")); err == nil {
		t.Fatal("expected error for unknown status, got nil")
	}
}
