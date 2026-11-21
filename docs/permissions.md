# Least-Privilege Read-Only Microsoft Graph Permissions

`blueprint-drift` is strictly **read-only by design**. It only issues HTTP `GET` requests to Microsoft Graph and never requests or requires any `*.ReadWrite.*` or write permission.

> **Disclaimer:** This is an independent community project. It is not produced, endorsed or supported by ASD, ACSC or Microsoft. Review every permission against the [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference) before granting admin consent in your tenant.

## Required permissions by workload

Grant only the permissions needed for the Blueprint domains you intend to check.

| Microsoft Graph permission | Type | Domains and endpoints covered | Purpose |
| --- | --- | --- | --- |
| `Policy.Read.All` | Application / Delegated | Entra ID: Conditional Access policies, named locations, authentication methods, authorization policy, security defaults, admin consent policy, cross-tenant access policy, device registration policy | Read identity and access security policies |
| `Organization.Read.All` | Application / Delegated | Entra ID: `/v1.0/organization` | Verify tenant country and data residency metadata |
| `Directory.Read.All` | Application / Delegated | Entra ID: `/beta/settings` (group creation, password protection) | Read directory-wide group and password protection settings |
| `RoleManagement.Read.Directory` | Application / Delegated | Entra ID PIM: `/v1.0/roleManagement/directory/roleAssignmentScheduleInstances` | Verify permanent vs eligible Global Administrator assignments |
| `DeviceManagementConfiguration.Read.All` | Application / Delegated | Intune and Defender for Endpoint: compliance policies, settings catalog configuration profiles, device management settings, security baseline intents, MTD connectors | Verify endpoint compliance and hardening policies |
| `DeviceManagementApps.Read.All` | Application / Delegated | Intune: iOS and Android managed app protection policies | Verify mobile application management (MAM) policies |
| `Domain.Read.All` | Application / Delegated | Exchange Online: `/v1.0/domains` | List verified accepted domains for email authentication inventory |
| `SharePointTenantSettings.Read.All` | Application / Delegated | SharePoint Online: `/v1.0/admin/sharepoint/settings` | Read tenant-wide sharing, OneDrive sync and idle session settings |
| `SecurityEvents.Read.All` | Application / Delegated | Microsoft Defender: `/v1.0/security/secureScores`, `/v1.0/security/secureScoreControlProfiles` | Read Microsoft Secure Score posture and control profiles |
| `SecurityIncident.Read.All` | Application / Delegated | Microsoft Defender: `/v1.0/security/incidents` | Verify Defender XDR incident visibility |
| `AuditLog.Read.All` | Application / Delegated | Audit correlation: `/v1.0/auditLogs/directoryAudits` | Optional: correlate configuration drift with who changed a setting and when |

## Authentication modes

### 1. App-only certificate authentication (recommended for scheduled CI/CD runs)

Follow the [Microsoft identity platform certificate credentials guide](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) to register a dedicated read-only Microsoft Entra application:

1. Register an application in your tenant (example tenant ID placeholder: `00000000-0000-0000-0000-000000000000`, example client ID placeholder: `11111111-1111-1111-1111-111111111111`).
2. Upload the public X.509 certificate (`.cer` / `.pem`) to the application registration. Store the private key securely in your key vault or CI secret store; never commit private keys to Git.
3. Grant admin consent **only** to the read-only Application permissions listed above.
4. `blueprint-drift` signs a short-lived RS256 JWT client assertion containing the certificate SHA-1 thumbprint (`x5t`) and exchanges it for a `https://graph.microsoft.com/.default` access token.

### 2. Delegated device code flow (for interactive assessor or operator runs)

Follow the [Microsoft identity platform device authorisation grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code):

1. Configure a public client application registration with the required read-only Delegated permissions.
2. Run `blueprint-drift` interactively; it displays the verification URL and user code and polls until sign-in completes with MFA.
3. Access is bounded by both the delegated scopes and the signed-in user's Entra ID RBAC role (for example **Global Reader** or **Security Reader**).

### 3. Optional `jusso-dev/junction` backend

If [jusso-dev/junction](https://github.com/jusso-dev/junction) is installed, pass `--backend junction --junction-context <context-name>`. `blueprint-drift` delegates Microsoft Graph execution and credential management to `junction` while still rejecting any write operation name before invocation.

## Read-only enforcement guarantees

`blueprint-drift` enforces read-only behaviour at three independent layers:

1. **Schema validation:** `blueprint/schema/settings.schema.json` requires `api_source.method == "GET"` and rejects any `Write` or `ReadWrite` permission string.
2. **HTTP transport guard:** `graph.ReadOnlyTransport` blocks any outbound Graph request whose HTTP method is not `GET` and validates the target host against the configured Microsoft Graph host allow-list (preventing bearer token leakage via untrusted `@odata.nextLink` redirects).
3. **CI static guard test:** `src/graph/readonly_guard_test.go` parses the Go AST of the Graph client and check packages on every PR to verify no non-GET Graph calls exist.
