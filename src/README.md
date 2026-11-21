# Core Source (`src/`)

Core packages for `blueprint-drift`:

- `src/engine/`: Setting models, rule evaluation and drift orchestration.
- `src/graph/`: Read-only Microsoft Graph client, auth flows, retry/paging and optional `jusso-dev/junction` backend (added in #5).
- `src/snapshot/`: Local snapshot persistence and snapshot diffing (added in #6).
- `src/audit/`: Entra ID and unified audit log correlation for drifted settings (added in #10).
