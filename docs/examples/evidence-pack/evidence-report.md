# IRAP Evidence Pack: ASD Blueprint for Secure Cloud Drift Assessment

> **Disclaimer:** Independent community project. Not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft.

## Run metadata

- **Run ID:** `run-20261121T000000Z`
- **Timestamp (UTC):** `2026-11-21T00:00:00Z`
- **Tenant ID:** `00000000-0000-0000-0000-000000000000`
- **Blueprint version:** `v1.4.0`

## Executive summary

| Metric | Count |
| --- | ---: |
| Total settings evaluated | 32 |
| Pass | 30 |
| Fail (drift detected) | 0 |
| Manual review required | 2 |
| Error | 0 |

## Setting evaluation results

| Setting ID | Section | Status | Severity | ISM Controls | Query | Response SHA-256 | Finding |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ENTRA-PROP-001` | Entra ID / Identity properties | `pass` | `high` | ISM-1507, ISM-1679 | `GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy` | `9c0982f319c6d8f3ec1410de249964f95de5b963a8b6fa9f4c08496e860a673b` | isEnabled equals expected value false |
| `ENTRA-PROP-002` | Entra ID / Identity properties | `pass` | `high` | ISM-1577 | `GET /v1.0/organization` | `b3c8f35971ec1a8414ae71cc9a3a81f1d9a79f24009c47b9a37a168c512286e0` | tenant countryLetterCode is AU |
| `ENTRA-USER-001` | Entra ID / User settings | `pass` | `high` | ISM-1507 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | defaultUserRolePermissions.allowedToCreateApps equals expected value false |
| `ENTRA-USER-002` | Entra ID / User settings | `pass` | `medium` | ISM-1507 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | defaultUserRolePermissions.allowedToCreateTenants equals expected value false |
| `ENTRA-USER-003` | Entra ID / User settings | `pass` | `medium` | ISM-0407 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | defaultUserRolePermissions.allowedToCreateSecurityGroups equals expected value false |
| `ENTRA-USER-004` | Entra ID / User settings | `pass` | `high` | ISM-0407, ISM-1405 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | guestUserRoleId equals expected value 2af84b1e-32c8-42b7-82bc-daa82404023b |
| `ENTRA-USER-005` | Entra ID / External identities | `pass` | `high` | ISM-0407 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | allowInvitesFrom (adminsAndGuestInviters) is in allowed set [none adminsAndGuestInviters] |
| `ENTRA-USER-006` | Entra ID / User settings | `pass` | `medium` | ISM-0407 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | blockMsolPowerShell equals expected value true |
| `ENTRA-USER-007` | Entra ID / User settings | `pass` | `medium` | ISM-0407 | `GET /beta/policies/authorizationPolicy` | `7fce34095353383a529b3a3899bb2932e91176d43c5c8f62feaf47628ae32b79` | defaultUserRolePermissions.allowedToReadOtherUsers equals expected value false |
| `ENTRA-APP-001` | Entra ID / Enterprise applications / Consent and permissions | `pass` | `high` | ISM-1507, ISM-1657 | `GET /v1.0/policies/authorizationPolicy` | `6c629dc8db336c8f0b80447071ed6851ed2787b03e314cf661bf82d9744b1c64` | defaultUserRolePermissions.permissionGrantPoliciesAssigned is empty (user consent disabled) |
| `ENTRA-APP-002` | Entra ID / Enterprise applications / Consent and permissions | `pass` | `medium` | ISM-1507 | `GET /v1.0/policies/adminConsentRequestPolicy` | `d918e54b28f1c27bf8498ef7a13ef906f7f3922e15a577ab3335fbcba5b09123` | isEnabled equals expected value true |
| `ENTRA-DEV-001` | Entra ID / Devices / Device settings | `pass` | `high` | ISM-0445, ISM-1647 | `GET /beta/policies/deviceRegistrationPolicy` | `d0140ab97a50e3dfe0ac866b9a36c6b4d3601cf16b82f0b9510f04357485edae` | localAdminPassword.isEnabled equals expected value true |
| `ENTRA-DEV-002` | Entra ID / Devices / Device settings | `pass` | `medium` | ISM-1507 | `GET /beta/policies/deviceRegistrationPolicy` | `d0140ab97a50e3dfe0ac866b9a36c6b4d3601cf16b82f0b9510f04357485edae` | Entra join configured (#microsoft.graph.enumeratedDeviceRegistrationMembership) with userDeviceQuota=5 |
| `ENTRA-DEV-003` | Entra ID / Devices / Device settings | `pass` | `low` | ISM-1507 | `GET /beta/policies/deviceRegistrationPolicy` | `d0140ab97a50e3dfe0ac866b9a36c6b4d3601cf16b82f0b9510f04357485edae` | multiFactorAuthConfiguration (notRequired) is in allowed set [notRequired required] |
| `ENTRA-EXT-001` | Entra ID / External identities / Cross-tenant access | `pass` | `high` | ISM-0407, ISM-1507 | `GET /v1.0/policies/crossTenantAccessPolicy/default` | `ac078e19a7a118d3dcf6cd79d0038586385fc15f3ee6cdab314afd194212b953` | default inbound B2B collaboration is blocked for users and applications |
| `ENTRA-GRP-001` | Entra ID / Groups / General | `pass` | `medium` | ISM-0407 | `GET /beta/settings` | `4098d893aa7df204b32a66ffc1c00dc07ece02b6d23848d880517d880a814a38` | Group.Unified EnableGroupCreation is false |
| `ENTRA-AUTH-001` | Entra ID / Protection / Authentication methods | `pass` | `critical` | ISM-1679, ISM-1681 | `GET /v1.0/policies/authenticationMethodsPolicy` | `324735e2f0c468894563d60c86736d771497c531b5bf9f47010ba433f3ca5c9d` | FIDO2 security key authentication method is enabled |
| `ENTRA-AUTH-002` | Entra ID / Protection / Authentication methods | `pass` | `critical` | ISM-1679, ISM-1681 | `GET /v1.0/policies/authenticationMethodsPolicy` | `324735e2f0c468894563d60c86736d771497c531b5bf9f47010ba433f3ca5c9d` | SMS, Voice and Email OTP authentication methods are disabled |
| `ENTRA-AUTH-003` | Entra ID / Protection / Authentication methods | `pass` | `medium` | ISM-1679 | `GET /v1.0/policies/authenticationMethodsPolicy` | `324735e2f0c468894563d60c86736d771497c531b5bf9f47010ba433f3ca5c9d` | TemporaryAccessPass enabled with maximumLifetimeInMinutes=480 |
| `ENTRA-AUTH-004` | Entra ID / Protection / Password protection | `pass` | `high` | ISM-0421, ISM-1403 | `GET /beta/settings` | `4098d893aa7df204b32a66ffc1c00dc07ece02b6d23848d880517d880a814a38` | custom banned password list enabled, smart lockout threshold=10, duration=60s |
| `ENTRA-AUTH-005` | Entra ID / Protection / Authentication methods | `pass` | `medium` | ISM-1679 | `GET /v1.0/policies/authenticationMethodsPolicy` | `324735e2f0c468894563d60c86736d771497c531b5bf9f47010ba433f3ca5c9d` | systemCredentialPreferences.state equals expected value enabled |
| `ENTRA-CA-001` | Entra ID / Conditional Access / Named locations | `pass` | `high` | ISM-1507 | `GET /v1.0/identity/conditionalAccess/namedLocations` | `7f8c352d4c4f2a5df6a2e8ad2c1b97357664b0cd43fae0fecdc2b61a169ddd54` | country named location "Approved Countries - Australia" includes AU and excludes unknown regions |
| `ENTRA-CA-002` | Entra ID / Conditional Access / Policies | `pass` | `critical` | ISM-1507, ISM-1680 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Block access via legacy authentication" blocks legacy authentication |
| `ENTRA-CA-003` | Entra ID / Conditional Access / Policies | `pass` | `critical` | ISM-1679, ISM-1681 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Require strong phishing-resistant authentication" requires strong authentication for all users |
| `ENTRA-CA-004` | Entra ID / Conditional Access / Policies | `pass` | `high` | ISM-1507, ISM-1546 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Require compliant devices" enforces compliantDevice |
| `ENTRA-CA-005` | Entra ID / Conditional Access / Policies | `pass` | `critical` | ISM-1507 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Block high-risk users" blocks high-risk users |
| `ENTRA-CA-006` | Entra ID / Conditional Access / Policies | `pass` | `critical` | ISM-1507 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Block high-risk sign-ins" blocks high-risk sign-ins |
| `ENTRA-CA-007` | Entra ID / Conditional Access / Policies | `pass` | `high` | ISM-1507 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Block unapproved countries" blocks access outside approved named locations |
| `ENTRA-CA-008` | Entra ID / Conditional Access / Policies | `pass` | `high` | ISM-0445, ISM-1507 | `GET /v1.0/identity/conditionalAccess/policies` | `6e932b8690878d7ceeb573ab4a4eff1ab75eb546dce763f0b3f6e76c7a562356` | enabled policy "BP - Limit administrator sessions" limits admin sessions (4 hours, persistentBrowser=never) |
| `ENTRA-PIM-001` | Entra ID / Identity governance / Privileged Identity Management | `pass` | `critical` | ISM-0445, ISM-1175 | `GET /v1.0/roleManagement/directory/roleAssignmentScheduleInstances` | `131d282f3ec7e97077aa03d0519ef2014d36cdb9d0a6f925070b9b4631e6e936` | 2 permanent active Global Administrator assignment(s) found (maximum 2) |
| `ENTRA-BG-001` | Entra ID / Users / Break-glass accounts | `manual` | `high` | ISM-0445, ISM-1175 | `manual` | N/A | Operational credential storage, physical vaulting, alerting rules and periodic break-glass testing records cannot be verified solely through Microsoft Graph. |
| `ENTRA-SSPR-001` | Entra ID / Protection / Password reset | `manual` | `low` | ISM-0421 | `manual` | N/A | Microsoft Entra self-service password reset portal notification and customisation settings have no full GA read-only Microsoft Graph API. |

## ISM control mapping summary

| ISM Control | Pass | Fail | Manual | Error | Settings |
| --- | ---: | ---: | ---: | ---: | --- |
| `ISM-0407` | 7 | 0 | 0 | 0 | ENTRA-EXT-001, ENTRA-GRP-001, ENTRA-USER-003, ENTRA-USER-004, ENTRA-USER-005, ENTRA-USER-006, ENTRA-USER-007 |
| `ISM-0421` | 1 | 0 | 1 | 0 | ENTRA-AUTH-004, ENTRA-SSPR-001 |
| `ISM-0445` | 3 | 0 | 1 | 0 | ENTRA-BG-001, ENTRA-CA-008, ENTRA-DEV-001, ENTRA-PIM-001 |
| `ISM-1175` | 1 | 0 | 1 | 0 | ENTRA-BG-001, ENTRA-PIM-001 |
| `ISM-1403` | 1 | 0 | 0 | 0 | ENTRA-AUTH-004 |
| `ISM-1405` | 1 | 0 | 0 | 0 | ENTRA-USER-004 |
| `ISM-1507` | 15 | 0 | 0 | 0 | ENTRA-APP-001, ENTRA-APP-002, ENTRA-CA-001, ENTRA-CA-002, ENTRA-CA-004, ENTRA-CA-005, ENTRA-CA-006, ENTRA-CA-007, ENTRA-CA-008, ENTRA-DEV-002, ENTRA-DEV-003, ENTRA-EXT-001, ENTRA-PROP-001, ENTRA-USER-001, ENTRA-USER-002 |
| `ISM-1546` | 1 | 0 | 0 | 0 | ENTRA-CA-004 |
| `ISM-1577` | 1 | 0 | 0 | 0 | ENTRA-PROP-002 |
| `ISM-1647` | 1 | 0 | 0 | 0 | ENTRA-DEV-001 |
| `ISM-1657` | 1 | 0 | 0 | 0 | ENTRA-APP-001 |
| `ISM-1679` | 6 | 0 | 0 | 0 | ENTRA-AUTH-001, ENTRA-AUTH-002, ENTRA-AUTH-003, ENTRA-AUTH-005, ENTRA-CA-003, ENTRA-PROP-001 |
| `ISM-1680` | 1 | 0 | 0 | 0 | ENTRA-CA-002 |
| `ISM-1681` | 3 | 0 | 0 | 0 | ENTRA-AUTH-001, ENTRA-AUTH-002, ENTRA-CA-003 |

## Manual items checklist for IRAP assessor

The following 2 setting(s) have no read-only Microsoft Graph API and require manual or PowerShell verification:

### `ENTRA-BG-001`: Emergency access account operational governance

- **Section:** Entra ID / Users / Break-glass accounts
- **Severity:** `high`
- **ISM Controls:** ISM-0445, ISM-1175
- **Reason manual:** Operational credential storage, physical vaulting, alerting rules and periodic break-glass testing records cannot be verified solely through Microsoft Graph.
- **Verification guidance:** Confirm two cloud-only Global Administrator emergency accounts exist, are excluded from Conditional Access policies, have sign-in alert rules configured in Sentinel or Azure Monitor, and have current test logs.

### `ENTRA-SSPR-001`: Self-service password reset notifications and customisation

- **Section:** Entra ID / Protection / Password reset
- **Severity:** `low`
- **ISM Controls:** ISM-0421
- **Reason manual:** Microsoft Entra self-service password reset portal notification and customisation settings have no full GA read-only Microsoft Graph API.
- **Verification guidance:** Inspect Entra admin center -> Protection -> Password reset (Properties, Authentication methods, Registration and Notifications) and record evidence screenshots for the IRAP assessor.

