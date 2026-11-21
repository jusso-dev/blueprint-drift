package main

import (
	"fmt"
	"io"
	"os"
)

var (
	version = "0.1.0-dev"
	commit  = "none"
)

func run(args []string, stdout io.Writer) int {
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version" || args[0] == "-v") {
		fmt.Fprintf(stdout, "blueprint-drift %s (%s)\n", version, commit)
		return 0
	}
	fmt.Fprintf(stdout, "blueprint-drift %s: read-only ASD Blueprint for Secure Cloud drift checker\n", version)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}
