# Domain Checks (`checks/`)

Read-only check implementations mapped to settings in `blueprint/`:

- `checks/entra/`: Microsoft Entra ID, Conditional Access, authentication methods, PIM and external identities (#7).
- `checks/intune/`: Microsoft Intune compliance policies, configuration profiles, endpoint security and app protection (#8).
- `checks/m365/`: Exchange Online, SharePoint Online, Microsoft Teams and Microsoft Defender checks plus manual item markers (#9).

Every check runs read-only against Microsoft Graph responses or fixture data and produces deterministic `engine.CheckResult` records.
