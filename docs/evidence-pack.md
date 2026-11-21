# IRAP Evidence Pack Guide

`blueprint-drift scan` produces a deterministic, self-contained evidence pack designed to support an [Information Security Registered Assessors Program (IRAP)](https://www.cyber.gov.au/resources-business-and-government/assessment-and-assurance/irap) assessment against the [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) and the [Information Security Manual (ISM)](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism).

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft.

## Generated artefacts

Every run writes five files into the configured `--out` directory:

| File | Purpose |
| --- | --- |
| `evidence-report.md` | Human-readable GitHub-flavoured Markdown summary, setting table, ISM control map and manual assessor checklist |
| `evidence-report.html` | Self-contained offline HTML report (zero external scripts or CDN assets) suitable for air-gapped review or PDF print |
| `evidence-report.csv` | Flat spreadsheet-friendly export for IRAP assessment workbooks and compliance tracking |
| `evidence-report.json` | Machine-readable structured output including full results, ISM summary and manual checklist |
| `evidence-manifest.json` | SHA-256 digests of all four generated report files for tamper-evident archiving |

## Provenance and reproducibility

Each automated check result records:

- **UTC timestamp** (`RFC3339`)
- **Target tenant ID** (placeholder `00000000-0000-0000-0000-000000000000` in fixture runs)
- **Exact read-only Microsoft Graph query** (for example `GET /v1.0/policies/authorizationPolicy`)
- **Reproducible response SHA-256 hash:** Raw Microsoft Graph JSON responses are canonicalised (keys sorted deterministically) before hashing with SHA-256, ensuring identical tenant states produce identical hashes across Windows, macOS and Linux.
- **ISM control and Essential Eight mappings**

## Manual assessor checklist

Settings with no documented read-only Microsoft Graph API are explicitly surfaced in the **Manual items checklist for IRAP assessor** section of every format alongside the reason automation is unavailable and the recommended portal or PowerShell verification step.

## Sample evidence pack from fixtures

A complete sample evidence pack generated offline from the compliant Entra ID fixtures (`checks/entra/testdata/compliant`) is available in [docs/examples/evidence-pack/](examples/evidence-pack/):

- [evidence-report.md](examples/evidence-pack/evidence-report.md)
- [evidence-report.html](examples/evidence-pack/evidence-report.html)
- [evidence-report.csv](examples/evidence-pack/evidence-report.csv)
- [evidence-report.json](examples/evidence-pack/evidence-report.json)
- [evidence-manifest.json](examples/evidence-pack/evidence-manifest.json)

Regenerate the sample pack locally at any time:

```sh
go run ./cmd/blueprint-drift scan \
  --blueprint blueprint/settings \
  --fixtures checks/entra/testdata/compliant \
  --out docs/examples/evidence-pack \
  --tenant-id 00000000-0000-0000-0000-000000000000 \
  --timestamp 2026-11-21T00:00:00Z
```
