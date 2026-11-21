package entra

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
)

const globalAdministratorRoleID = "62e90394-69f5-4237-9190-012177145e10"

// Register registers all Microsoft Entra ID and Conditional Access check rules.
func Register(reg *engine.Registry) {
	reg.Register("entra_org_country_au", checkOrgCountryAU)
	reg.Register("entra_user_consent_disabled", checkUserConsentDisabled)
	reg.Register("entra_device_join_controlled", checkDeviceJoinControlled)
	reg.Register("entra_cross_tenant_inbound_blocked", checkCrossTenantInboundBlocked)
	reg.Register("entra_group_creation_disabled", checkGroupCreationDisabled)
	reg.Register("entra_auth_fido2_enabled", checkAuthFIDO2Enabled)
	reg.Register("entra_auth_weak_methods_disabled", checkAuthWeakMethodsDisabled)
	reg.Register("entra_auth_tap_bounded", checkAuthTAPBounded)
	reg.Register("entra_password_protection_enabled", checkPasswordProtectionEnabled)
	reg.Register("entra_named_location_au", checkNamedLocationAU)
	reg.Register("ca_block_legacy_auth", checkCABlockLegacyAuth)
	reg.Register("ca_require_strong_auth", checkCARequireStrongAuth)
	reg.Register("ca_require_compliant_device", checkCARequireCompliantDevice)
	reg.Register("ca_block_high_risk_users", checkCABlockHighRiskUsers)
	reg.Register("ca_block_high_risk_sign_ins", checkCABlockHighRiskSignIns)
	reg.Register("ca_block_unapproved_countries", checkCABlockUnapprovedCountries)
	reg.Register("ca_limit_admin_sessions", checkCALimitAdminSessions)
	reg.Register("entra_pim_global_admin_max_2", checkPIMGlobalAdminMax2)
}

func checkOrgCountryAU(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			CountryLetterCode string `json:"countryLetterCode"`
			DisplayName       string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || len(resp.Value) == 0 {
		return false, nil, "no organization record returned by Graph"
	}
	code := strings.ToUpper(strings.TrimSpace(resp.Value[0].CountryLetterCode))
	if code == "AU" {
		return true, code, "tenant countryLetterCode is AU"
	}
	return false, code, fmt.Sprintf("tenant countryLetterCode is %q; expected AU", code)
}

func checkUserConsentDisabled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		DefaultUserRolePermissions struct {
			PermissionGrantPoliciesAssigned []string `json:"permissionGrantPoliciesAssigned"`
		} `json:"defaultUserRolePermissions"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid authorizationPolicy payload: %v", err)
	}
	assigned := resp.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
	if len(assigned) == 0 {
		return true, assigned, "defaultUserRolePermissions.permissionGrantPoliciesAssigned is empty (user consent disabled)"
	}
	return false, assigned, fmt.Sprintf("user consent policies assigned: %v; expected none", assigned)
}

func checkDeviceJoinControlled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		AzureADJoin struct {
			AllowedToJoin struct {
				ODataType string `json:"@odata.type"`
			} `json:"allowedToJoin"`
		} `json:"azureADJoin"`
		UserDeviceQuota int `json:"userDeviceQuota"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceRegistrationPolicy payload: %v", err)
	}
	joinType := resp.AzureADJoin.AllowedToJoin.ODataType
	quota := resp.UserDeviceQuota
	actual := map[string]any{"allowedToJoin": joinType, "userDeviceQuota": quota}
	if (strings.Contains(joinType, "enumeratedDeviceRegistrationMembership") || strings.Contains(joinType, "allDeviceRegistrationMembership")) && quota > 0 && quota <= 20 {
		return true, actual, fmt.Sprintf("Entra join configured (%s) with userDeviceQuota=%d", joinType, quota)
	}
	return false, actual, fmt.Sprintf("Entra join policy does not meet baseline (type=%q, userDeviceQuota=%d)", joinType, quota)
}

func checkCrossTenantInboundBlocked(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		B2BCollaborationInbound struct {
			UsersAndGroups struct {
				AccessType string `json:"accessType"`
			} `json:"usersAndGroups"`
			Applications struct {
				AccessType string `json:"accessType"`
			} `json:"applications"`
		} `json:"b2bCollaborationInbound"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid crossTenantAccessPolicy payload: %v", err)
	}
	users := strings.ToLower(resp.B2BCollaborationInbound.UsersAndGroups.AccessType)
	apps := strings.ToLower(resp.B2BCollaborationInbound.Applications.AccessType)
	actual := map[string]string{"usersAndGroups": users, "applications": apps}
	if users == "blocked" && apps == "blocked" {
		return true, actual, "default inbound B2B collaboration is blocked for users and applications"
	}
	return false, actual, fmt.Sprintf("default inbound B2B collaboration is not fully blocked (users=%q, apps=%q)", users, apps)
}

type directorySettingsResp struct {
	Value []struct {
		DisplayName string `json:"displayName"`
		Values      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"values"`
	} `json:"value"`
}

func findDirectorySettingValue(raw []byte, groupName, key string) (string, bool) {
	var resp directorySettingsResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", false
	}
	for _, g := range resp.Value {
		if strings.EqualFold(g.DisplayName, groupName) {
			for _, kv := range g.Values {
				if strings.EqualFold(kv.Name, key) {
					return kv.Value, true
				}
			}
		}
	}
	return "", false
}

func checkGroupCreationDisabled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	val, ok := findDirectorySettingValue(raw, "Group.Unified", "EnableGroupCreation")
	if !ok {
		return false, nil, "Group.Unified EnableGroupCreation setting not configured (defaults to true)"
	}
	if strings.EqualFold(val, "false") {
		return true, false, "Group.Unified EnableGroupCreation is false"
	}
	return false, val, fmt.Sprintf("Group.Unified EnableGroupCreation is %q; expected false", val)
}

func checkPasswordProtectionEnabled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	enableCustom, ok1 := findDirectorySettingValue(raw, "Password Rule Settings", "EnableBannedPasswordCheck")
	thresholdStr, ok2 := findDirectorySettingValue(raw, "Password Rule Settings", "LockoutThreshold")
	durationStr, ok3 := findDirectorySettingValue(raw, "Password Rule Settings", "LockoutDurationInSeconds")
	if !ok1 || !ok2 || !ok3 {
		return false, nil, "Password Rule Settings directory setting is incomplete or missing"
	}
	threshold, err1 := strconv.Atoi(thresholdStr)
	duration, err2 := strconv.Atoi(durationStr)
	actual := map[string]any{
		"EnableBannedPasswordCheck": enableCustom,
		"LockoutThreshold":          thresholdStr,
		"LockoutDurationInSeconds":  durationStr,
	}
	if err1 == nil && err2 == nil && strings.EqualFold(enableCustom, "true") && threshold > 0 && threshold <= 10 && duration >= 60 {
		return true, actual, fmt.Sprintf("custom banned password list enabled, smart lockout threshold=%d, duration=%ds", threshold, duration)
	}
	return false, actual, fmt.Sprintf("password protection does not meet Blueprint baseline: %v", actual)
}

type authMethodsPolicyResp struct {
	AuthenticationMethodConfigurations []struct {
		ID                       string `json:"id"`
		State                    string `json:"state"`
		DefaultLifetimeInMinutes int    `json:"defaultLifetimeInMinutes"`
		MaximumLifetimeInMinutes int    `json:"maximumLifetimeInMinutes"`
	} `json:"authenticationMethodConfigurations"`
}

func checkAuthFIDO2Enabled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp authMethodsPolicyResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid authenticationMethodsPolicy payload: %v", err)
	}
	for _, cfg := range resp.AuthenticationMethodConfigurations {
		if strings.EqualFold(cfg.ID, "Fido2") {
			if strings.EqualFold(cfg.State, "enabled") {
				return true, cfg.State, "FIDO2 security key authentication method is enabled"
			}
			return false, cfg.State, fmt.Sprintf("FIDO2 authentication method state is %q; expected enabled", cfg.State)
		}
	}
	return false, nil, "Fido2 configuration not found in authenticationMethodsPolicy"
}

func checkAuthWeakMethodsDisabled(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp authMethodsPolicyResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid authenticationMethodsPolicy payload: %v", err)
	}
	weakIDs := map[string]bool{"sms": true, "voice": true, "email": true}
	states := make(map[string]string)
	var enabledWeak []string
	for _, cfg := range resp.AuthenticationMethodConfigurations {
		id := strings.ToLower(cfg.ID)
		if weakIDs[id] {
			states[cfg.ID] = cfg.State
			if !strings.EqualFold(cfg.State, "disabled") {
				enabledWeak = append(enabledWeak, fmt.Sprintf("%s=%s", cfg.ID, cfg.State))
			}
		}
	}
	if len(enabledWeak) == 0 && len(states) > 0 {
		return true, states, "SMS, Voice and Email OTP authentication methods are disabled"
	}
	if len(states) == 0 {
		return false, states, "no SMS/Voice/Email authentication method entries found in response"
	}
	return false, states, fmt.Sprintf("weak authentication method(s) still active: %s", strings.Join(enabledWeak, ", "))
}

func checkAuthTAPBounded(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp authMethodsPolicyResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid authenticationMethodsPolicy payload: %v", err)
	}
	for _, cfg := range resp.AuthenticationMethodConfigurations {
		if strings.EqualFold(cfg.ID, "TemporaryAccessPass") {
			actual := map[string]any{
				"state":                    cfg.State,
				"maximumLifetimeInMinutes": cfg.MaximumLifetimeInMinutes,
			}
			if strings.EqualFold(cfg.State, "enabled") && cfg.MaximumLifetimeInMinutes > 0 && cfg.MaximumLifetimeInMinutes <= 480 {
				return true, actual, fmt.Sprintf("TemporaryAccessPass enabled with maximumLifetimeInMinutes=%d", cfg.MaximumLifetimeInMinutes)
			}
			return false, actual, fmt.Sprintf("TemporaryAccessPass does not meet baseline (state=%q, maxLifetime=%d)", cfg.State, cfg.MaximumLifetimeInMinutes)
		}
	}
	return false, nil, "TemporaryAccessPass configuration not found"
}

func checkNamedLocationAU(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ODataType             string   `json:"@odata.type"`
			DisplayName           string   `json:"displayName"`
			CountriesAndRegions   []string `json:"countriesAndRegions"`
			IncludeUnknownRegions bool     `json:"includeUnknownCountriesAndRegions"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid namedLocations payload: %v", err)
	}
	for _, loc := range resp.Value {
		if strings.Contains(loc.ODataType, "countryNamedLocation") {
			for _, c := range loc.CountriesAndRegions {
				if strings.EqualFold(c, "AU") && !loc.IncludeUnknownRegions {
					return true, loc.DisplayName, fmt.Sprintf("country named location %q includes AU and excludes unknown regions", loc.DisplayName)
				}
			}
		}
	}
	return false, nil, "no countryNamedLocation found including AU with includeUnknownCountriesAndRegions=false"
}

type caPoliciesResp struct {
	Value []caPolicy `json:"value"`
}

type caPolicy struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		ClientAppTypes   []string `json:"clientAppTypes"`
		SignInRiskLevels []string `json:"signInRiskLevels"`
		UserRiskLevels   []string `json:"userRiskLevels"`
		Users            struct {
			IncludeUsers []string `json:"includeUsers"`
			IncludeRoles []string `json:"includeRoles"`
		} `json:"users"`
		Applications struct {
			IncludeApplications []string `json:"includeApplications"`
		} `json:"applications"`
		Locations *struct {
			IncludeLocations []string `json:"includeLocations"`
			ExcludeLocations []string `json:"excludeLocations"`
		} `json:"locations"`
	} `json:"conditions"`
	GrantControls *struct {
		Operator               string   `json:"operator"`
		BuiltInControls        []string `json:"builtInControls"`
		AuthenticationStrength *struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"authenticationStrength"`
	} `json:"grantControls"`
	SessionControls *struct {
		SignInFrequency *struct {
			Value     int    `json:"value"`
			Type      string `json:"type"`
			IsEnabled bool   `json:"isEnabled"`
		} `json:"signInFrequency"`
		PersistentBrowser *struct {
			Mode      string `json:"mode"`
			IsEnabled bool   `json:"isEnabled"`
		} `json:"persistentBrowser"`
	} `json:"sessionControls"`
}

func containsIgnoreCase(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func enabledCAPolicies(raw []byte) ([]caPolicy, error) {
	var resp caPoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	var enabled []caPolicy
	for _, p := range resp.Value {
		if strings.EqualFold(p.State, "enabled") {
			enabled = append(enabled, p)
		}
	}
	return enabled, nil
}

func checkCABlockLegacyAuth(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls == nil || !containsIgnoreCase(p.GrantControls.BuiltInControls, "block") {
			continue
		}
		if containsIgnoreCase(p.Conditions.Users.IncludeUsers, "All") &&
			containsIgnoreCase(p.Conditions.Applications.IncludeApplications, "All") &&
			containsIgnoreCase(p.Conditions.ClientAppTypes, "exchangeActiveSync") &&
			containsIgnoreCase(p.Conditions.ClientAppTypes, "other") {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q blocks legacy authentication", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found blocking exchangeActiveSync and other legacy clients for All users and All apps"
}

func checkCARequireStrongAuth(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls == nil {
			continue
		}
		allUsers := containsIgnoreCase(p.Conditions.Users.IncludeUsers, "All")
		allApps := containsIgnoreCase(p.Conditions.Applications.IncludeApplications, "All")
		hasMFA := containsIgnoreCase(p.GrantControls.BuiltInControls, "mfa")
		hasStrength := p.GrantControls.AuthenticationStrength != nil && p.GrantControls.AuthenticationStrength.ID != ""
		if allUsers && allApps && (hasMFA || hasStrength) {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q requires strong authentication for all users", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found requiring MFA or authentication strength for all users"
}

func checkCARequireCompliantDevice(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls != nil && containsIgnoreCase(p.GrantControls.BuiltInControls, "compliantDevice") {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q enforces compliantDevice", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found requiring compliantDevice"
}

func checkCABlockHighRiskUsers(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls != nil &&
			containsIgnoreCase(p.GrantControls.BuiltInControls, "block") &&
			containsIgnoreCase(p.Conditions.UserRiskLevels, "high") {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q blocks high-risk users", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found blocking high-risk users"
}

func checkCABlockHighRiskSignIns(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls != nil &&
			containsIgnoreCase(p.GrantControls.BuiltInControls, "block") &&
			containsIgnoreCase(p.Conditions.SignInRiskLevels, "high") {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q blocks high-risk sign-ins", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found blocking high-risk sign-ins"
}

func checkCABlockUnapprovedCountries(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if p.GrantControls != nil &&
			p.Conditions.Locations != nil &&
			containsIgnoreCase(p.GrantControls.BuiltInControls, "block") &&
			containsIgnoreCase(p.Conditions.Locations.IncludeLocations, "All") &&
			len(p.Conditions.Locations.ExcludeLocations) > 0 {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q blocks access outside approved named locations", p.DisplayName)
		}
	}
	return false, nil, "no enabled Conditional Access policy found blocking unapproved countries/locations"
}

func checkCALimitAdminSessions(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	policies, err := enabledCAPolicies(raw)
	if err != nil {
		return false, nil, fmt.Sprintf("invalid Conditional Access policies payload: %v", err)
	}
	for _, p := range policies {
		if len(p.Conditions.Users.IncludeRoles) == 0 || p.SessionControls == nil {
			continue
		}
		sif := p.SessionControls.SignInFrequency
		pb := p.SessionControls.PersistentBrowser
		if sif != nil && sif.IsEnabled && sif.Value > 0 && pb != nil && pb.IsEnabled && strings.EqualFold(pb.Mode, "never") {
			return true, p.DisplayName, fmt.Sprintf("enabled policy %q limits admin sessions (%d %s, persistentBrowser=never)", p.DisplayName, sif.Value, sif.Type)
		}
	}
	return false, nil, "no enabled Conditional Access policy found limiting privileged role sessions with signInFrequency and persistentBrowser=never"
}

func checkPIMGlobalAdminMax2(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			PrincipalID      string  `json:"principalId"`
			RoleDefinitionID string  `json:"roleDefinitionId"`
			AssignmentType   string  `json:"assignmentType"`
			EndDateTime      *string `json:"endDateTime"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid roleAssignmentScheduleInstances payload: %v", err)
	}

	permanent := 0
	for _, item := range resp.Value {
		if !strings.EqualFold(item.RoleDefinitionID, globalAdministratorRoleID) {
			continue
		}
		isPermanent := item.EndDateTime == nil || strings.TrimSpace(*item.EndDateTime) == ""
		if strings.EqualFold(item.AssignmentType, "Assigned") && isPermanent {
			permanent++
		}
	}
	if permanent <= 2 {
		return true, permanent, fmt.Sprintf("%d permanent active Global Administrator assignment(s) found (maximum 2)", permanent)
	}
	return false, permanent, fmt.Sprintf("%d permanent active Global Administrator assignments found; Blueprint maximum is 2 (break-glass only)", permanent)
}
