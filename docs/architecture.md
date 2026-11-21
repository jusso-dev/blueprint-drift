# Architecture Diagrams

This document illustrates the `blueprint-drift` drift engine, read-only authentication flows and IRAP evidence pipeline using GitHub-compatible Mermaid diagrams.

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft.

## 1. Drift engine and read-only collection architecture

```mermaid
flowchart TB
    subgraph Definitions["Blueprint Definitions (blueprint/)"]
        YAML["Setting Catalogs (YAML)"]
        SCHEMA["JSON Schema (settings.schema.json)"]
    end

    subgraph Engine["Drift Engine (src/engine)"]
        LOADER["Schema Validator and Loader (src/blueprint)"]
        RUNNER["Drift Runner with Per-Run Endpoint Cache"]
        REG["Rule Registry (checks/entra, checks/intune, checks/m365)"]
    end

    subgraph GraphLayer["Read-Only Graph Layer (src/graph)"]
        DIRECT["DirectClient (default)"]
        JUNCTION["JunctionClient (optional jusso-dev/junction)"]
        FIXTURE["FixtureClient (offline tests)"]
        GUARD["ReadOnlyTransport (GET-only + Host Allow-List)"]
    end

    subgraph Cloud["Microsoft Cloud (Read-Only)"]
        GRAPH["Microsoft Graph API (v1.0 / beta)"]
    end

    subgraph Outputs["Persistence and IRAP Evidence"]
        SNAP["Local Snapshot Store (src/snapshot)"]
        DIFF["Drift Diff Engine"]
        AUDIT["Audit Log Correlator (src/audit)"]
        PACK["Evidence Pack Renderer (evidence/)"]
    end

    YAML --> LOADER
    SCHEMA -. validates .-> LOADER
    LOADER --> RUNNER
    RUNNER --> DIRECT
    RUNNER --> JUNCTION
    RUNNER --> FIXTURE
    DIRECT --> GUARD
    GUARD -->|"HTTP GET + Retries + Paging"| GRAPH
    JUNCTION -->|"Read-only junction execute"| GRAPH
    GRAPH -->|"Canonical JSON + SHA-256"| RUNNER
    RUNNER --> REG
    REG --> SNAP
    REG --> PACK
    SNAP --> DIFF
    AUDIT --> DIFF
```

## 2. Authentication and least-privilege read-only flow

`blueprint-drift` supports app-only X.509 certificate credentials ([Microsoft identity platform certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)), interactive delegated device code flow ([Microsoft identity platform device code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)), and optional delegation to [jusso-dev/junction](https://github.com/jusso-dev/junction).

```mermaid
sequenceDiagram
    participant Op as Operator or CI Pipeline
    participant CLI as blueprint-drift CLI
    participant Auth as Auth Provider (src/graph/auth.go)
    participant Entra as Microsoft Entra OAuth 2.0
    participant Guard as ReadOnlyTransport
    participant Graph as Microsoft Graph API

    alt App-only certificate flow (CI/CD)
        Op->>CLI: scan --cert app.pem --key app.key
        CLI->>Auth: Request access token
        Auth->>Auth: Sign RS256 JWT assertion with x5t thumbprint
        Auth->>Entra: POST /oauth2/v2.0/token (client_credentials)
        Entra-->>Auth: Read-only Bearer access token
    else Delegated device code flow (Interactive)
        Op->>CLI: scan --backend direct
        CLI->>Auth: Request delegated token
        Auth->>Entra: POST /oauth2/v2.0/devicecode (Read.All scopes)
        Entra-->>Auth: verification_uri + user_code
        Auth-->>Op: Display sign-in code prompt
        Op->>Entra: Complete interactive MFA sign-in
        Auth->>Entra: Poll POST /oauth2/v2.0/token
        Entra-->>Auth: Delegated read-only Bearer token
    end

    CLI->>Guard: GET /v1.0/... or /beta/...
    Guard->>Guard: Verify method == GET and host in allow-list
    Guard->>Graph: HTTPS GET with Bearer token
    Graph-->>Guard: JSON payload (429/503 retried with Retry-After)
    Guard-->>CLI: Canonical JSON + reproducible SHA-256 digest
```

## 3. Evidence pack and continuous drift pipeline flow

This flow aligns snapshot storage, drift attribution and tamper-evident report generation for an [IRAP](https://www.cyber.gov.au/resources-business-and-government/assessment-and-assurance/irap) assessment against the [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) and [ISM](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism).

```mermaid
flowchart LR
    TRIGGER["Scheduled Pipeline (GitHub Actions / Azure DevOps)"] --> SCAN["blueprint-drift scan"]
    SCAN --> CANON["Canonical JSON Normalisation + SHA-256"]
    CANON --> CURR["Current Snapshot (snapshots/run-T2.json)"]
    CANON --> PACK["IRAP Evidence Pack"]

    subgraph EvidencePack["Evidence Pack Artefacts (evidence/)"]
        MD["evidence-report.md"]
        HTML["evidence-report.html (offline)"]
        CSV["evidence-report.csv"]
        JSON["evidence-report.json"]
        MAN["evidence-manifest.json (SHA-256 digests)"]
    end

    PACK --> EvidencePack
    EvidencePack --> IRAP["IRAP Assessor Review (Automated + Manual Checklist + ISM Map)"]

    PREV["Previous Snapshot (snapshots/run-T1.json)"] --> DIFF["blueprint-drift diff --fail-on-drift"]
    CURR --> DIFF
    ENTRA_AUD["Entra directoryAudits"] --> CORR["Audit Correlator (who and when)"]
    UAL["Purview Unified Audit Export"] --> CORR
    CORR --> DIFF
    DIFF -->|"Exit code 3 (drift)"| ISSUE["Open GitHub Issue or Azure Boards Work Item"]
    DIFF -->|"Exit code 0 (clean)"| ARCHIVE["Archive Artefacts (90-day retention)"]
```
