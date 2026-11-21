# Blueprint Settings Inventory

This directory holds the research inventory and machine-readable definitions derived from the [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/).

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft. Always verify configuration baselines against the current official [Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) and the [Information Security Manual (ISM)](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism).

## Source provenance

Metadata is tracked in [metadata.yaml](metadata.yaml).

- **Source publication:** ASD Blueprint for Secure Cloud ([blueprint.asd.gov.au](https://blueprint.asd.gov.au/))
- **Source repository:** [ASD-Blueprint/ASD-Blueprint-for-Secure-Cloud](https://github.com/ASD-Blueprint/ASD-Blueprint-for-Secure-Cloud)
- **Blueprint release version:** `v1.4.0`
- **Source commit SHA:** `a6e1e5f95e6051f23d2e7d1148c8fd57a6614000`
- **Source commit date:** `2026-09-18`
- **Retrieval date:** `2026-11-21`

## Scope and API coverage summary

The full setting-by-setting inventory is recorded in [inventory.md](inventory.md). It covers five core Microsoft 365 and Entra security domains in the Blueprint:

| Domain | Total settings inventoried | Automatable via Microsoft Graph | Manual or PowerShell-only |
| --- | ---: | ---: | ---: |
| Microsoft Entra ID and Conditional Access | 32 | 30 | 2 |
| Microsoft Intune | 16 | 14 | 2 |
| Exchange Online | 10 | 1 | 9 |
| SharePoint Online and Microsoft Teams | 13 | 5 | 8 |
| Microsoft Defender | 12 | 5 | 7 |
| **Total** | **83** | **55** | **28** |

## API classification rules

Each inventoried setting in [inventory.md](inventory.md) is assigned one of two collection modes:

1. **Microsoft Graph (`v1.0` or `beta`):** Read-only `GET` endpoint documented in the [Microsoft Graph REST API reference](https://learn.microsoft.com/en-us/graph/overview). Least-privilege read permissions are recorded per endpoint.
2. **`manual`:** No documented read-only Microsoft Graph REST API currently exposes the setting. This includes workloads that require Exchange Online PowerShell (`ExchangeOnlineManagement`), Microsoft Teams PowerShell (`MicrosoftTeams`), Security and Compliance PowerShell, DNS queries outside Graph, or Microsoft Defender portal UI verification. Manual items are still tracked in evidence packs so an IRAP assessor has a complete checklist.

## Official references

- [ASD Blueprint for Secure Cloud](https://blueprint.asd.gov.au/)
- [ASD Information Security Manual (ISM)](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism)
- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [Microsoft Graph REST API v1.0 reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0)
- [Microsoft Graph REST API beta reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta)
