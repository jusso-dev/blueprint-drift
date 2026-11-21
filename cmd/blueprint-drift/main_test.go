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

func TestRunScanAndDiffSnapshots(t *testing.T) {
	bpDir := filepath.Join("..", "..", "blueprint", "settings")
	fxDir := filepath.Join("..", "..", "checks", "entra", "testdata", "compliant")
	outDir := t.TempDir()
	snapDir := t.TempDir()

	var out, errOut bytes.Buffer
	code := run([]string{
		"scan",
		"--blueprint", bpDir,
		"--domain", "entra-id",
		"--fixtures", fxDir,
		"--out", outDir,
		"--snapshot-dir", snapDir,
		"--timestamp", "2026-11-20T00:00:00Z",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan 1 failed (%d): %s", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{
		"scan",
		"--blueprint", bpDir,
		"--domain", "entra-id",
		"--fixtures", fxDir,
		"--out", outDir,
		"--snapshot-dir", snapDir,
		"--timestamp", "2026-11-21T00:00:00Z",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan 2 failed (%d): %s", code, errOut.String())
	}

	// Identical fixtures should produce zero drift even with --fail-on-drift.
	out.Reset()
	errOut.Reset()
	code = run([]string{
		"diff",
		"--store", snapDir,
		"--from", "run-20261120T000000Z",
		"--to", "run-20261121T000000Z",
		"--fail-on-drift",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0 for identical snapshots, got %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "No drift detected") {
		t.Fatalf("expected no drift output, got:\n%s", out.String())
	}

	// Mutate the second snapshot on disk to simulate drift and verify exit code 3.
	snap2Path := filepath.Join(snapDir, "run-20261121T000000Z.json")
	raw, err := os.ReadFile(snap2Path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(raw), `"status": "pass"`, `"status": "fail"`, 1)
	if err := os.WriteFile(snap2Path, []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errOut.Reset()
	code = run([]string{
		"diff",
		"--store", snapDir,
		"--from", "run-20261120T000000Z",
		"--to", "run-20261121T000000Z",
		"--format", "markdown",
		"--fail-on-drift",
	}, &out, &errOut)
	if code != 3 {
		t.Fatalf("expected exit code 3 on drift, got %d (stdout: %s, stderr: %s)", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "regressed") {
		t.Fatalf("expected regression in markdown diff:\n%s", out.String())
	}
}
