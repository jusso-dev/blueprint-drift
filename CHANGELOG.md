# Changelog

All notable changes to `blueprint-drift` are documented in this file.

## v1.0.0 (2026-11-21)

Initial production release of `blueprint-drift`:

- **Blueprint inventory and schema:** 83 settings derived from the ASD Blueprint for Secure Cloud `v1.4.0` (55 automatable read-only Microsoft Graph checks + 28 clearly documented manual or PowerShell-only checks), validated against JSON Schema Draft 2020-12 (`blueprint/schema/settings.schema.json`).
- **Read-only Microsoft Graph client:** App-only X.509 certificate authentication (RS256 JWT assertion with `x5t`), delegated OAuth 2.0 device code authentication, optional `jusso-dev/junction` backend, `429`/`503`/`504` throttling retries, `@odata.nextLink` pagination, transport-level GET-only guard and CI static AST read-only guard.
- **Domain checks:** Fixture-tested evaluators for Microsoft Entra ID and Conditional Access, Microsoft Intune, Exchange Online, SharePoint Online, Microsoft Teams and Microsoft Defender.
- **Snapshots, diff and audit correlation:** Atomic local JSON snapshot store, per-setting drift diffing (`added`, `removed`, `changed`, `regressed`, `remediated`) with exit code `3` on `--fail-on-drift`, and read-only correlation with Entra directory audit logs and Purview unified audit exports.
- **IRAP evidence packs:** Reproducible Markdown, offline HTML, CSV and JSON reports plus SHA-256 manifest (`evidence-manifest.json`), ISM control summary and manual assessor checklist.
- **Automation and packaging:** Scheduled GitHub Actions and Azure DevOps pipeline examples, Mermaid architecture diagrams, signed cross-platform binaries (Linux, macOS, Windows), SHA-256 checksums and distroless container image.
