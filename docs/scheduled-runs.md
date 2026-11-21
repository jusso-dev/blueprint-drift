# Scheduled Drift Monitoring in GitHub Actions and Azure DevOps

`blueprint-drift` is designed to run unattended on a daily or weekly schedule in CI/CD pipelines, archiving snapshots and IRAP evidence packs as build artefacts and opening a tracking issue or work item whenever tenant configuration drifts.

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by ASD, ACSC or Microsoft.

## Pipeline examples

| Platform | Example file | Official documentation |
| --- | --- | --- |
| GitHub Actions | [blueprint-drift-scheduled.yml](examples/github-actions/blueprint-drift-scheduled.yml) | [GitHub Actions schedule event](https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#schedule) |
| Azure DevOps Pipelines | [blueprint-drift-scheduled.yml](examples/azure-devops/blueprint-drift-scheduled.yml) | [Azure Pipelines scheduled triggers](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/scheduled-triggers) |

## Prerequisites

1. Register a dedicated **read-only** Microsoft Entra ID application with certificate credentials as documented in [docs/permissions.md](permissions.md) and the [Microsoft identity platform certificate credentials guide](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).
2. Store the following values in GitHub Actions secrets or an Azure Key Vault-backed Azure DevOps Variable Group (never commit real IDs or private keys):
   - `BLUEPRINT_TENANT_ID`: Target tenant GUID (placeholder example: `00000000-0000-0000-0000-000000000000`)
   - `BLUEPRINT_CLIENT_ID`: Read-only application client GUID (placeholder example: `11111111-1111-1111-1111-111111111111`)
   - `BLUEPRINT_CERT_PEM`: X.509 public certificate (PEM)
   - `BLUEPRINT_KEY_PEM`: Matching RSA private key (PEM)
3. Keep pipeline permissions least-privilege:
   - **GitHub Actions:** `contents: read`, `actions: read`, `issues: write`
   - **Azure DevOps:** Grant the build service account permission to create work items in the target project and download prior pipeline artefacts.

## How drift alerting works

1. The pipeline downloads the previous `blueprint-drift-snapshots` artefact from the last successful scheduled run.
2. `blueprint-drift scan` reads the tenant via read-only Microsoft Graph `GET` calls, writes a new canonical snapshot JSON file and generates all four IRAP evidence formats (`md`, `html`, `csv`, `json`) plus `evidence-manifest.json`.
3. `blueprint-drift diff --from <prev> --to <curr> --format markdown --fail-on-drift` compares the two snapshots per setting.
   - Exit code `0`: No drift detected.
   - Exit code `3`: Drift detected; the pipeline opens a GitHub Issue or Azure Boards work item containing the Markdown diff report.
4. Both the snapshot directory and the IRAP evidence pack are uploaded as retained build artefacts (90 days recommended for continuous assurance, or exported to immutable storage for full IRAP assessment cycles).
5. Temporary certificate/key files on the runner are deleted in an `always()` cleanup step.
