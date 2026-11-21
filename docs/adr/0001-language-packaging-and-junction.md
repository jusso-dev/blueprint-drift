# ADR 0001: Implementation language, cross-platform packaging and junction integration

- **Status:** Accepted
- **Date:** 2026-11-21
- **Context issue:** [#2](https://github.com/jusso-dev/blueprint-drift/issues/2)

## Context

`blueprint-drift` compares a Microsoft 365 and Microsoft Entra ID tenant read-only against settings derived from the [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) via the [Microsoft Graph REST API](https://learn.microsoft.com/en-us/graph/overview) and generates evidence packs suitable for an [IRAP](https://www.cyber.gov.au/resources-business-and-government/assessment-and-assurance/irap) assessment.

The project has four core packaging and integration requirements:

1. Distribute as a single self-contained binary for Windows, macOS and Linux, plus a minimal container image for CI/CD pipelines.
2. Require no external runtime (such as Python, PowerShell or Node.js) on the operator workstation or build runner.
3. Keep the read-only security boundary auditable and verifiable through automated tests.
4. Support [jusso-dev/junction](https://github.com/jusso-dev/junction) as an optional Microsoft Graph backend while working standalone with no external backend installed.

## Options considered

### Implementation language

| Criterion | Go | Rust | Python |
| --- | --- | --- | --- |
| Single static binary | Native (`CGO_ENABLED=0`), trivial cross-compilation across `windows`, `darwin` and `linux` | Native static binary; cross-compilation requires target toolchains or per-OS runners | Requires PyInstaller/Nuitka bundling or host Python runtime |
| Standard library coverage | `net/http`, `crypto/sha256`, `crypto/rsa`, `crypto/x509`, `encoding/json`, `encoding/csv`, `html/template`, `embed` built in | Minimal standard library; relies on external crates (`reqwest`, `tokio`, `serde`, `ring`/`rustls`) | Rich standard library, but poor single-binary story |
| Build and CI speed | Fast native compilation (seconds across 3 OSes) | Slower clean builds in CI, larger dependency graph | Fast execution, slower packaging |
| Auditability for IRAP | Small dependency tree; HTTP transport guard and AST checks are straightforward | Strong type safety; larger crate dependency tree to audit | Runtime environment and dependency pinning add audit surface |

### Junction integration model

1. **Compile-time library embedding:** Linking `junction` Rust crates directly would lock `blueprint-drift` to Rust and pull a large generated API registry into every binary.
2. **Optional out-of-process adapter (CLI or local HTTP):** Define a minimal read-only `GraphClient` interface in `blueprint-drift` with two implementations:
   - `direct` (default): native Go `net/http` client calling `https://graph.microsoft.com` read-only (`GET`) using app-only certificate authentication or delegated device code flow ([Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-overview)).
   - `junction` (optional): invokes a local `junction` binary (or local Junction HTTP server) using its read-only execution mode, delegating authentication, cloud context selection and throttling to `junction`.

## Decision

1. **Language:** Implement `blueprint-drift` in **Go** (minimum Go 1.24).
   - Binaries are built statically with `CGO_ENABLED=0` for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` and `windows/amd64`.
   - Container images use a minimal distroless or `scratch` runtime stage containing only the compiled binary and CA certificates.
   - Local snapshot storage uses canonical JSON files with an index manifest so `CGO_ENABLED=0` remains intact across all platforms and stored snapshots remain human-auditable.
2. **Junction integration:** Integrate [jusso-dev/junction](https://github.com/jusso-dev/junction) as an **optional backend** selected via `--backend junction` (with `--backend direct` as the default).
   - Both backends satisfy the same read-only `GraphClient` interface, which permits HTTP `GET` operations only and returns the canonical query path, status code, raw response bytes and SHA-256 digest required for IRAP evidence packs.
   - Because the `junction` backend communicates over a clean JSON contract (CLI subprocess or local HTTP), `blueprint-drift` has zero compile-time coupling to `junction` and operates standalone when `junction` is absent.
3. **Repository layout:** Retain the documented layout from [README.md](../../README.md):
   - `cmd/blueprint-drift/`: CLI entrypoint
   - `src/`: Drift engine, Graph client, auth, snapshot store and audit log correlation
   - `checks/`: Domain check implementations (Entra ID, Intune, Exchange, SharePoint, Teams, Defender)
   - `evidence/`: IRAP evidence pack templates and renderers
   - `blueprint/`: Machine-readable Blueprint settings, schema and provenance metadata
   - `docs/`: Architecture decision records, operational guides and diagrams

## Consequences

- **Positive:** Fast cross-platform builds across Windows, macOS and Linux in CI; minimal third-party dependency tree; clean separation between direct Graph calls and optional `junction` execution; straightforward static analysis and transport-level read-only enforcement.
- **Negative:** Go lacks native compile-time access to `junction-types` Rust structs, so Graph response fields used by checks are modelled as small Go structs tailored to each Blueprint setting.
- **Mitigation:** Fixture-based unit tests validate every check against realistic Microsoft Graph JSON payloads aligned to the [Microsoft Graph REST API reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0).

## Disclaimer

This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft.
