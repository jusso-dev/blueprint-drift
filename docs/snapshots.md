# Snapshot Store and Drift Diff

`blueprint-drift` persists point-in-time tenant evaluation results as canonical JSON files in a local snapshot store directory so operators and CI pipelines can detect configuration drift over time without requiring a database engine or native C dependencies (`CGO_ENABLED=0`).

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by ASD, ACSC or Microsoft.

## Directory layout

```text
snapshots/
  index.json                    # Chronological manifest of stored runs
  run-20261120T000000Z.json     # Full snapshot for a single run
  run-20261121T000000Z.json     # Subsequent run snapshot
```

All snapshot files and `index.json` are written atomically (write to temporary file, then rename) to prevent partial writes from corrupting the store.

## Snapshot JSON format (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "run_id": "run-20261121T000000Z",
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "blueprint_version": "v1.4.0",
  "captured_at": "2026-11-21T00:00:00Z",
  "summary": {
    "total": 32,
    "pass": 30,
    "fail": 0,
    "manual": 2,
    "error": 0
  },
  "snapshot_sha256": "<sha256-of-canonical-settings-map>",
  "settings": {
    "ENTRA-PROP-001": {
      "setting_id": "ENTRA-PROP-001",
      "section": "Entra ID / Identity properties",
      "title": "Security defaults disabled in favour of Conditional Access",
      "status": "pass",
      "severity": "high",
      "expected": false,
      "actual": false,
      "message": "isEnabled equals expected value false",
      "query": "GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
      "response_sha256": "<sha256-of-canonical-graph-response>",
      "ism_controls": ["ISM-1507", "ISM-1679"]
    }
  }
}
```

## CLI usage

### Save a snapshot during a scan

```sh
blueprint-drift scan \
  --blueprint blueprint/settings \
  --fixtures checks/entra/testdata/compliant \
  --out evidence-pack \
  --snapshot-dir snapshots
```

### Diff two snapshots

Compare two snapshots by file path or by run ID inside `--store`:

```sh
blueprint-drift diff \
  --store snapshots \
  --from run-20261120T000000Z \
  --to run-20261121T000000Z \
  --format markdown \
  --fail-on-drift
```

Supported output formats: `text` (default), `markdown`, `json`.

### Change classification and exit codes

Each differing setting is classified by kind (`added`, `removed`, `changed`) and posture direction (`regressed`, `remediated`, `modified`, `added`, `removed`).

| Exit code | Meaning |
| ---: | --- |
| `0` | Diff completed (no drift, or `--fail-on-drift` not set) |
| `1` | Runtime or I/O error |
| `2` | Invalid CLI flags |
| `3` | Drift detected while `--fail-on-drift` is enabled |
