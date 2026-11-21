# blueprint-drift

Cross-platform drift checker that compares a Microsoft 365 and Entra tenant against the [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) via Microsoft Graph and produces evidence ready for [IRAP](https://www.cyber.gov.au/resources-business-and-government/assessment-and-assurance/irap).

## Goal

The ASD Blueprint for Secure Cloud describes how to configure Microsoft 365, Entra ID and Intune securely, but existing tooling only checks part of it and does not track drift over time. `blueprint-drift`:

1. Reads tenant configuration read-only through Microsoft Graph (optionally through [jusso-dev/junction](https://github.com/jusso-dev/junction)).
2. Compares it to a machine-readable copy of the Blueprint settings (`v1.4.0`, 83 settings across Entra ID, Intune, Exchange Online, SharePoint Online, Microsoft Teams and Microsoft Defender).
3. Stores canonical JSON snapshots so you can see what changed, when, and by whom (correlated with Entra directory audit logs and Microsoft Purview unified audit exports).
4. Produces an IRAP-ready evidence pack (Markdown, HTML, CSV, JSON and SHA-256 manifest) with timestamps, the read-only Graph query used, the canonical response hash, ISM control mappings and a manual assessor checklist.

It runs on Windows, macOS and Linux as a single static Go binary (`CGO_ENABLED=0`) or minimal container image, and in GitHub Actions or Azure DevOps on a schedule.

## Quick start

```sh
# Validate all Blueprint YAML catalogs against the JSON Schema
go run ./cmd/blueprint-drift validate --blueprint blueprint/settings

# Run an offline fixture scan and generate an IRAP evidence pack + snapshot
go run ./cmd/blueprint-drift scan \
  --blueprint blueprint/settings \
  --domain entra-id \
  --fixtures checks/entra/testdata/compliant \
  --snapshot-dir snapshots \
  --out evidence-pack

# Diff two snapshots and fail with exit code 3 on drift
go run ./cmd/blueprint-drift diff \
  --store snapshots \
  --from run-20261120T000000Z \
  --to run-20261121T000000Z \
  --format markdown \
  --fail-on-drift
```

## Layout

```text
blueprint/       Machine-readable Blueprint settings (YAML), JSON Schema and inventory
cmd/             CLI entrypoint (blueprint-drift)
src/             Drift engine, schema loader, read-only Graph client, snapshots and audit correlation
checks/          Domain check implementations (Entra ID, Intune, Exchange, SharePoint, Teams, Defender)
evidence/        IRAP evidence pack templates and renderers
docs/            Guides, ADRs, architecture diagrams and pipeline examples
```

## Documentation

- [Architecture diagrams](docs/architecture.md)
- [ADR 0001: Language, packaging and junction integration](docs/adr/0001-language-packaging-and-junction.md)
- [Blueprint settings inventory](blueprint/inventory.md)
- [Least-privilege read-only Graph permissions](docs/permissions.md)
- [IRAP evidence pack guide](docs/evidence-pack.md) and [sample pack](docs/examples/evidence-pack/)
- [Snapshot store and drift diff](docs/snapshots.md)
- [Audit log correlation](docs/audit-correlation.md)
- [Scheduled runs in GitHub Actions and Azure DevOps](docs/scheduled-runs.md)

## Related projects

- [microsoft-security-logging-guide](https://github.com/jusso-dev/microsoft-security-logging-guide): which Microsoft security logs matter and how to get them into Sentinel
- [soc-ready-logging](https://github.com/jusso-dev/soc-ready-logging)
- [junction](https://github.com/jusso-dev/junction): Microsoft API runtime (Graph, Defender, Sentinel)

## Disclaimer

This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft. References to ASD publications, the ISM and the Essential Eight point to the official sources; always check the current release.

## Licence

Code and content are released under the [MIT License](LICENSE).
