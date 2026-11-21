# Audit Log Correlation for Configuration Drift

When `blueprint-drift diff` detects that a setting has drifted between two snapshots, it can optionally correlate each drifted setting with Microsoft Entra ID directory audit logs and Microsoft Purview unified audit log exports to show **who** made the change and **when**.

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by ASD, ACSC or Microsoft.

## Audit data sources

| Source | Endpoint / input | Retention (typical) | Official reference |
| --- | --- | --- | --- |
| Microsoft Entra ID directory audits | `GET /v1.0/auditLogs/directoryAudits` (`AuditLog.Read.All`) | 30 days (Entra ID P1/P2) or 7 days (Free) | [List directoryAudits API](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) |
| Microsoft Purview unified audit log | Exported JSON via `--unified-audit <path>` (or Purview Audit Search) | 180 days (Audit Standard) or 1+ year (Audit Premium) | [Microsoft Purview Audit solutions](https://learn.microsoft.com/en-us/purview/audit-solutions-overview) |

## Usage

Correlate drift against offline audit fixtures or a Purview unified audit JSON export:

```sh
blueprint-drift diff \
  --store snapshots \
  --from run-20261120T000000Z \
  --to run-20261121T000000Z \
  --audit-fixtures path/to/audit-fixtures \
  --unified-audit path/to/unified-audit.json \
  --format markdown
```

## Graceful handling of missing audit data

Audit correlation never fails a drift diff run:

- If `AuditLog.Read.All` is not granted (HTTP 403), or if no audit client is configured, `blueprint-drift` records an explanatory `audit_note` on each drifted item and completes the diff report cleanly.
- If the snapshot window falls outside the tenant's audit retention window or no matching event exists, `audit_note` records `no matching audit event found in snapshot window`.
