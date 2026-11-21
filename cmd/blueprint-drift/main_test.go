package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDefault(t *testing.T) {
	var out bytes.Buffer
	code := run(nil, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "blueprint-drift") {
		t.Fatalf("expected banner output, got %q", out.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"version"}, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), version) {
		t.Fatalf("expected version %q in output, got %q", version, out.String())
	}
}
