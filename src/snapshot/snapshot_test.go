package snapshot_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/snapshot"
)

func TestStoreSaveLoadListAndLatest(t *testing.T) {
	store := snapshot.NewStore(t.TempDir())

	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	snap1, err := snapshot.FromRun(&engine.RunResult{
		RunID:            "run-20261120T100000Z",
		TenantID:         "00000000-0000-0000-0000-000000000000",
		BlueprintVersion: "v1.4.0",
		GeneratedAt:      t1,
		Summary:          engine.Summary{Total: 1, Pass: 1},
		Results: []engine.CheckResult{
			{SettingID: "ENTRA-PROP-001", Status: engine.StatusPass, Actual: false, ResponseSHA256: "aaa"},
		},
	})
	if err != nil {
		t.Fatalf("FromRun 1: %v", err)
	}
	snap2, err := snapshot.FromRun(&engine.RunResult{
		RunID:            "run-20261121T100000Z",
		TenantID:         "00000000-0000-0000-0000-000000000000",
		BlueprintVersion: "v1.4.0",
		GeneratedAt:      t2,
		Summary:          engine.Summary{Total: 1, Fail: 1},
		Results: []engine.CheckResult{
			{SettingID: "ENTRA-PROP-001", Status: engine.StatusFail, Actual: true, ResponseSHA256: "bbb"},
		},
	})
	if err != nil {
		t.Fatalf("FromRun 2: %v", err)
	}

	if _, err := store.Save(snap2); err != nil {
		t.Fatalf("Save snap2: %v", err)
	}
	if _, err := store.Save(snap1); err != nil {
		t.Fatalf("Save snap1: %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 || entries[0].RunID != snap1.RunID || entries[1].RunID != snap2.RunID {
		t.Fatalf("expected chronological ordering, got %+v", entries)
	}

	latest, err := store.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.RunID != snap2.RunID {
		t.Fatalf("expected latest %s, got %s", snap2.RunID, latest.RunID)
	}

	loaded, err := store.Load(snap1.RunID)
	if err != nil {
		t.Fatalf("Load by run ID: %v", err)
	}
	if loaded.SnapshotSHA256 != snap1.SnapshotSHA256 {
		t.Fatalf("snapshot digest mismatch: %s vs %s", loaded.SnapshotSHA256, snap1.SnapshotSHA256)
	}
}

func TestDiffAddedRemovedRegressedAndRemediated(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	from := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		RunID:         "run-1",
		TenantID:      "00000000-0000-0000-0000-000000000000",
		CapturedAt:    t1,
		Settings: map[string]snapshot.SettingSnapshot{
			"ENTRA-PROP-001": {SettingID: "ENTRA-PROP-001", Status: engine.StatusPass, Severity: engine.SeverityHigh, Actual: false, ResponseSHA256: "h1"},
			"ENTRA-USER-001": {SettingID: "ENTRA-USER-001", Status: engine.StatusFail, Severity: engine.SeverityHigh, Actual: true, ResponseSHA256: "h2"},
			"ENTRA-OLD-001":  {SettingID: "ENTRA-OLD-001", Status: engine.StatusPass, Severity: engine.SeverityLow, Actual: true, ResponseSHA256: "h3"},
			"ENTRA-SAME-001": {SettingID: "ENTRA-SAME-001", Status: engine.StatusPass, Severity: engine.SeverityLow, Actual: true, ResponseSHA256: "h4"},
		},
	}
	to := &snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		RunID:         "run-2",
		TenantID:      "00000000-0000-0000-0000-000000000000",
		CapturedAt:    t2,
		Settings: map[string]snapshot.SettingSnapshot{
			"ENTRA-PROP-001": {SettingID: "ENTRA-PROP-001", Status: engine.StatusFail, Severity: engine.SeverityHigh, Actual: true, ResponseSHA256: "h1-new"},
			"ENTRA-USER-001": {SettingID: "ENTRA-USER-001", Status: engine.StatusPass, Severity: engine.SeverityHigh, Actual: false, ResponseSHA256: "h2-new"},
			"ENTRA-NEW-001":  {SettingID: "ENTRA-NEW-001", Status: engine.StatusPass, Severity: engine.SeverityMedium, Actual: "AU", ResponseSHA256: "h5"},
			"ENTRA-SAME-001": {SettingID: "ENTRA-SAME-001", Status: engine.StatusPass, Severity: engine.SeverityLow, Actual: true, ResponseSHA256: "h4"},
		},
	}

	diff := snapshot.Diff(from, to)
	if !diff.HasDrift() {
		t.Fatal("expected drift to be detected")
	}
	if diff.Added != 1 || diff.Removed != 1 || diff.Changed != 2 || diff.Regressed != 1 || diff.Remediated != 1 {
		t.Fatalf("unexpected diff counts: %+v", diff)
	}

	text := snapshot.RenderText(diff)
	if !strings.Contains(text, "ENTRA-PROP-001") || !strings.Contains(text, "regressed") {
		t.Fatalf("unexpected text diff output:\n%s", text)
	}
	md := snapshot.RenderMarkdown(diff)
	if !strings.Contains(md, "# Blueprint Drift Diff Report") || !strings.Contains(md, "ENTRA-NEW-001") {
		t.Fatalf("unexpected markdown diff output:\n%s", md)
	}
	rawJSON, err := snapshot.RenderJSON(diff)
	if err != nil || !strings.Contains(string(rawJSON), `"regressed": 1`) {
		t.Fatalf("unexpected JSON diff output: err=%v body=%s", err, string(rawJSON))
	}
}
