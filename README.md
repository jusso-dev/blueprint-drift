# blueprint-drift

Cross-platform drift checker that compares a Microsoft 365 and Entra tenant against the ASD Blueprint for Secure Cloud via Microsoft Graph and produces evidence ready for IRAP.

> **Status:** early build. Work is tracked in [issues](https://github.com/jusso-dev/blueprint-drift/issues).

## Goal

The ASD Blueprint for Secure Cloud describes how to configure Microsoft 365, Entra ID and Intune securely, but existing tooling only checks part of it and does not track drift over time. blueprint-drift:

1. Reads tenant configuration read-only through Microsoft Graph (optionally through [jusso-dev/junction](https://github.com/jusso-dev/junction)).
2. Compares it to a machine readable copy of the Blueprint settings.
3. Stores snapshots so you can see what changed, when, and by whom (correlated with audit logs).
4. Produces an evidence pack (Markdown, HTML, CSV and JSON) with timestamps, the Graph query used and the raw response hash, suitable to hand to an IRAP assessor.

It runs on Windows, macOS and Linux as a single binary or container, and in GitHub Actions or Azure DevOps on a schedule.

## Layout

```
blueprint/       Machine readable Blueprint settings (YAML)
src/             Drift engine and Graph client
checks/          Check implementations
evidence/        Report templates
docs/            Guides, ADRs, diagrams
```

## Related projects

- [microsoft-security-logging-guide](https://github.com/jusso-dev/microsoft-security-logging-guide): which Microsoft security logs matter and how to get them into Sentinel
- [soc-ready-logging](https://github.com/jusso-dev/soc-ready-logging)
- [junction](https://github.com/jusso-dev/junction): Microsoft API runtime (Graph, Defender, Sentinel)

## Disclaimer

This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft. References to ASD publications, the ISM and the Essential Eight point to the official sources; always check the current release.

## Licence

Code and content are released under the [MIT License](LICENSE).
