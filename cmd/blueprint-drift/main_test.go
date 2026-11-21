package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDefault(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "blueprint-drift") {
		t.Fatalf("expected banner output, got %q", out.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), version) {
		t.Fatalf("expected version %q in output, got %q", version, out.String())
	}
}

func TestRunValidate(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := filepath.Join("..", "..", "blueprint", "settings")
	code := run([]string{"validate", "--blueprint", dir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Validated") {
		t.Fatalf("expected validation summary, got %q", out.String())
	}
}

func TestRunScanFixtures(t *testing.T) {
	var out, errOut bytes.Buffer
	bpDir := filepath.Join("..", "..", "blueprint", "settings")
	fxDir := filepath.Join("..", "..", "checks", "entra", "testdata", "compliant")
	outDir := t.TempDir()

	code := run([]string{
		"scan",
		"--blueprint", bpDir,
		"--fixtures", fxDir,
		"--out", outDir,
		"--timestamp", "2026-11-21T00:00:00Z",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, errOut.String())
	}
	for _, name := range []string{
		"evidence-report.md",
		"evidence-report.html",
		"evidence-report.csv",
		"evidence-report.json",
		"evidence-manifest.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected artefact %s to exist: %v", name, err)
		}
	}
}
