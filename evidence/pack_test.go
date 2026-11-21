package evidence_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jusso-dev/blueprint-drift/checks/entra"
	"github.com/jusso-dev/blueprint-drift/evidence"
	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

func buildFixtureRun(t *testing.T) *engine.RunResult {
	t.Helper()
	catPath := filepath.Join("..", "blueprint", "settings", "entra-id.yaml")
	cat, err := blueprint.LoadFile(catPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	fxDir := filepath.Join("..", "checks", "entra", "testdata", "compliant")
	fx, err := graph.LoadFixtureDir(fxDir)
	if err != nil {
		t.Fatalf("LoadFixtureDir: %v", err)
	}
	reg := engine.NewRegistry()
	entra.Register(reg)

	fixedTime := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	runner := &engine.Runner{
		Client:   fx,
		Registry: reg,
		TenantID: "00000000-0000-0000-0000-000000000000",
		Now:      func() time.Time { return fixedTime },
	}
	res, err := runner.Run(context.Background(), []*blueprint.Catalog{cat})
	if err != nil {
		t.Fatalf("Runner.Run: %v", err)
	}
	return res
}

func TestWritePackFourFormatsAndReproducibleHashes(t *testing.T) {
	run := buildFixtureRun(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	m1, err := evidence.WritePack(run, dir1)
	if err != nil {
		t.Fatalf("WritePack dir1: %v", err)
	}
	m2, err := evidence.WritePack(run, dir2)
	if err != nil {
		t.Fatalf("WritePack dir2: %v", err)
	}

	expectedFiles := []string{
		"evidence-report.md",
		"evidence-report.html",
		"evidence-report.csv",
		"evidence-report.json",
	}

	for _, name := range expectedFiles {
		h1, ok1 := m1.Artefacts[name]
		h2, ok2 := m2.Artefacts[name]
		if !ok1 || !ok2 || h1 == "" {
			t.Fatalf("missing SHA-256 digest for %s", name)
		}
		if h1 != h2 {
			t.Fatalf("hash for %s not reproducible: %s vs %s", name, h1, h2)
		}
	}

	// Verify Markdown contains required IRAP fields and manual assessor checklist.
	mdBytes, err := os.ReadFile(filepath.Join(dir1, "evidence-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	md := string(mdBytes)
	for _, needle := range []string{
		"00000000-0000-0000-0000-000000000000",
		"2026-11-21T00:00:00Z",
		"ENTRA-CA-002",
		"ISM-1507",
		"Manual items checklist for IRAP assessor",
		"ENTRA-BG-001",
	} {
		if !strings.Contains(md, needle) {
			t.Errorf("markdown report missing %q", needle)
		}
	}

	// Verify HTML is valid self-contained document with expected content.
	htmlBytes, err := os.ReadFile(filepath.Join(dir1, "evidence-report.html"))
	if err != nil {
		t.Fatal(err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "<!DOCTYPE html>") || !strings.Contains(htmlStr, "Manual Items Checklist for IRAP Assessor") {
		t.Fatalf("unexpected HTML output")
	}

	// Verify CSV row count matches header + 32 settings.
	csvBytes, err := os.ReadFile(filepath.Join(dir1, "evidence-report.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(csvBytes))).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != 33 {
		t.Fatalf("expected 33 CSV rows (header + 32 settings), got %d", len(rows))
	}

	// Verify JSON parses cleanly and includes ISM summary + manual items.
	jsonBytes, err := os.ReadFile(filepath.Join(dir1, "evidence-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed evidence.JSONReport
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("parse JSON report: %v", err)
	}
	if len(parsed.Results) != 32 || len(parsed.ManualItems) != 2 || len(parsed.ISMControlMap) == 0 {
		t.Fatalf("unexpected JSON report counts: results=%d manual=%d ism=%d", len(parsed.Results), len(parsed.ManualItems), len(parsed.ISMControlMap))
	}
}
