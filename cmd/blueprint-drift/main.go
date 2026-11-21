package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jusso-dev/blueprint-drift/checks/entra"
	"github.com/jusso-dev/blueprint-drift/evidence"
	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
	"github.com/jusso-dev/blueprint-drift/src/graph"
	"github.com/jusso-dev/blueprint-drift/src/snapshot"
)

var (
	version = "0.1.0-dev"
	commit  = "none"
)

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stdout, "blueprint-drift %s: read-only ASD Blueprint for Secure Cloud drift checker\n", version)
		fmt.Fprintln(stdout, "Usage: blueprint-drift <version|validate|scan|diff> [flags]")
		return 0
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "blueprint-drift %s (%s)\n", version, commit)
		return 0
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
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

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bpDir := fs.String("blueprint", "blueprint/settings", "Path to Blueprint YAML settings directory")
	fixturesDir := fs.String("fixtures", "", "Path to offline Graph JSON fixtures directory")
	outDir := fs.String("out", "evidence-pack", "Output directory for IRAP evidence pack")
	snapshotDir := fs.String("snapshot-dir", "", "Optional directory to persist a local JSON snapshot")
	tenantID := fs.String("tenant-id", "00000000-0000-0000-0000-000000000000", "Microsoft Entra tenant ID")
	backend := fs.String("backend", "direct", "Graph backend: direct, junction or fixtures")
	junctionBin := fs.String("junction-bin", "junction", "Path to junction binary when --backend junction")
	junctionCtx := fs.String("junction-context", "", "Junction context name when --backend junction")
	certPath := fs.String("cert", "", "Path to PEM certificate for app-only direct auth")
	keyPath := fs.String("key", "", "Path to PEM RSA private key for app-only direct auth")
	clientID := fs.String("client-id", "", "Microsoft Entra application client ID")
	timestampStr := fs.String("timestamp", "", "Optional fixed RFC3339 UTC timestamp for reproducible fixture runs")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	catalogs, err := blueprint.LoadDir(*bpDir)
	if err != nil {
		fmt.Fprintf(stderr, "load blueprint settings: %v\n", err)
		return 1
	}

	mode := *backend
	if *fixturesDir != "" {
		mode = "fixtures"
	}

	var client graph.Client
	switch mode {
	case "fixtures":
		if *fixturesDir == "" {
			fmt.Fprintln(stderr, "--fixtures directory is required for fixtures backend")
			return 2
		}
		client, err = graph.LoadFixtureDir(*fixturesDir)
		if err != nil {
			fmt.Fprintf(stderr, "load fixtures: %v\n", err)
			return 1
		}
	case "junction":
		ops := collectJunctionOps(catalogs)
		client = graph.NewJunctionClient(*junctionBin, *junctionCtx, ops)
	case "direct":
		if *certPath != "" && *keyPath != "" {
			cert, key, loadErr := graph.LoadCertificateAndKey(*certPath, *keyPath)
			if loadErr != nil {
				fmt.Fprintf(stderr, "load certificate/key: %v\n", loadErr)
				return 1
			}
			prov, authErr := graph.NewCertificateAuthProvider(graph.CertificateAuthConfig{
				TenantID:    *tenantID,
				ClientID:    *clientID,
				Certificate: cert,
				PrivateKey:  key,
			})
			if authErr != nil {
				fmt.Fprintf(stderr, "configure certificate auth: %v\n", authErr)
				return 1
			}
			client, err = graph.NewDirectClient(prov)
		} else {
			prov, authErr := graph.NewDeviceCodeAuthProvider(graph.DeviceCodeAuthConfig{
				TenantID: *tenantID,
				ClientID: *clientID,
				OnPrompt: func(p graph.DeviceCodePrompt) {
					fmt.Fprintln(stdout, p.Message)
				},
			})
			if authErr != nil {
				fmt.Fprintf(stderr, "configure device code auth: %v\n", authErr)
				return 1
			}
			client, err = graph.NewDirectClient(prov)
		}
		if err != nil {
			fmt.Fprintf(stderr, "initialise Graph client: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "unsupported backend %q (expected direct, junction or fixtures)\n", mode)
		return 2
	}

	nowFn := func() time.Time { return time.Now().UTC() }
	if *timestampStr != "" {
		parsed, parseErr := time.Parse(time.RFC3339, *timestampStr)
		if parseErr != nil {
			fmt.Fprintf(stderr, "invalid --timestamp (expected RFC3339): %v\n", parseErr)
			return 2
		}
		fixed := parsed.UTC()
		nowFn = func() time.Time { return fixed }
	}

	reg := engine.NewRegistry()
	entra.Register(reg)

	runner := &engine.Runner{
		Client:   client,
		Registry: reg,
		TenantID: *tenantID,
		Now:      nowFn,
	}

	runResult, err := runner.Run(context.Background(), catalogs)
	if err != nil {
		fmt.Fprintf(stderr, "drift scan failed: %v\n", err)
		return 1
	}

	manifest, err := evidence.WritePack(runResult, *outDir)
	if err != nil {
		fmt.Fprintf(stderr, "write evidence pack: %v\n", err)
		return 1
	}

	if *snapshotDir != "" {
		snap, snapErr := snapshot.FromRun(runResult)
		if snapErr != nil {
			fmt.Fprintf(stderr, "build snapshot: %v\n", snapErr)
			return 1
		}
		store := snapshot.NewStore(*snapshotDir)
		savedPath, saveErr := store.Save(snap)
		if saveErr != nil {
			fmt.Fprintf(stderr, "save snapshot: %v\n", saveErr)
			return 1
		}
		fmt.Fprintf(stdout, "Snapshot saved to %s\n", savedPath)
	}

	fmt.Fprintf(
		stdout,
		"Scan complete (%s): total=%d pass=%d fail=%d manual=%d error=%d. Evidence pack written to %s (%d artefacts).\n",
		runResult.RunID,
		runResult.Summary.Total,
		runResult.Summary.Pass,
		runResult.Summary.Fail,
		runResult.Summary.Manual,
		runResult.Summary.Error,
		*outDir,
		len(manifest.Artefacts),
	)
	return 0
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	storeDir := fs.String("store", "snapshots", "Snapshot store directory for resolving run IDs")
	fromRef := fs.String("from", "", "Baseline snapshot file path or run ID")
	toRef := fs.String("to", "", "Target snapshot file path or run ID")
	format := fs.String("format", "text", "Output format: text, markdown or json")
	outFile := fs.String("out", "", "Optional output file path (defaults to stdout)")
	failOnDrift := fs.Bool("fail-on-drift", false, "Exit with code 3 when drift is detected")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *fromRef == "" || *toRef == "" {
		fmt.Fprintln(stderr, "--from and --to are required")
		return 2
	}

	store := snapshot.NewStore(*storeDir)
	fromSnap, err := store.Load(*fromRef)
	if err != nil {
		fmt.Fprintf(stderr, "load --from snapshot: %v\n", err)
		return 1
	}
	toSnap, err := store.Load(*toRef)
	if err != nil {
		fmt.Fprintf(stderr, "load --to snapshot: %v\n", err)
		return 1
	}

	report := snapshot.Diff(fromSnap, toSnap)

	var output []byte
	switch *format {
	case "text":
		output = []byte(snapshot.RenderText(report))
	case "markdown", "md":
		output = []byte(snapshot.RenderMarkdown(report))
	case "json":
		output, err = snapshot.RenderJSON(report)
		if err != nil {
			fmt.Fprintf(stderr, "render diff JSON: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "unsupported format %q (expected text, markdown or json)\n", *format)
		return 2
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, output, 0o644); err != nil {
			fmt.Fprintf(stderr, "write diff output %s: %v\n", *outFile, err)
			return 1
		}
	} else {
		_, _ = stdout.Write(output)
	}

	if *failOnDrift && report.HasDrift() {
		return 3
	}
	return 0
}

func collectJunctionOps(catalogs []*blueprint.Catalog) map[string]string {
	ops := make(map[string]string)
	for _, cat := range catalogs {
		for _, s := range cat.Settings {
			if s.APISource.Kind == "graph" && s.APISource.JunctionOperation != "" {
				key := fmt.Sprintf("/%s%s", s.APISource.Version, s.APISource.Endpoint)
				ops[key] = s.APISource.JunctionOperation
			}
		}
	}
	return ops
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
