package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
)

var (
	version = "0.1.0-dev"
	commit  = "none"
)

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stdout, "blueprint-drift %s: read-only ASD Blueprint for Secure Cloud drift checker\n", version)
		fmt.Fprintln(stdout, "Usage: blueprint-drift <version|validate> [flags]")
		return 0
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "blueprint-drift %s (%s)\n", version, commit)
		return 0
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("blueprint", "blueprint/settings", "Path to Blueprint YAML settings directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	catalogs, err := blueprint.LoadDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return 1
	}

	total := 0
	for _, c := range catalogs {
		total += len(c.Settings)
	}
	fmt.Fprintf(stdout, "Validated %d setting(s) across %d catalog file(s) in %s.\n", total, len(catalogs), *dir)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
