package intune

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
)

// Register registers all Microsoft Intune check rules with the engine registry.
func Register(reg *engine.Registry) {
	reg.Register("intune_win_compliance_hardware", checkWinComplianceHardware)
	reg.Register("intune_win_compliance_defender", checkWinComplianceDefender)
	reg.Register("intune_win_compliance_threat_level", checkWinComplianceThreatLevel)
	reg.Register("intune_ios_compliance_baseline", checkIOSComplianceBaseline)
	reg.Register("intune_cfg_windows_hardening", checkCfgWindowsHardening)
	reg.Register("intune_cfg_office_macros", checkCfgOfficeMacros)
	reg.Register("intune_cfg_edge_hardening", checkCfgEdgeHardening)
	reg.Register("intune_cfg_ios_profile", checkCfgIOSProfile)
	reg.Register("intune_sec_asr_policy", checkSecASRPolicy)
	reg.Register("intune_sec_baselines_present", checkSecBaselinesPresent)
	reg.Register("intune_app_ios_protection", checkAppIOSProtection)
	reg.Register("intune_app_android_protection", checkAppAndroidProtection)
}

type compliancePoliciesResp struct {
	Value []struct {
		ODataType                                 string `json:"@odata.type"`
		DisplayName                               string `json:"displayName"`
		BitLockerEnabled                          bool   `json:"bitLockerEnabled"`
		SecureBootEnabled                         bool   `json:"secureBootEnabled"`
		CodeIntegrityEnabled                      bool   `json:"codeIntegrityEnabled"`
		DefenderEnabled                           bool   `json:"defenderEnabled"`
		RTPEnabled                                bool   `json:"rtpEnabled"`
		FirewallEnabled                           bool   `json:"firewallEnabled"`
		AntivirusRequired                         bool   `json:"antivirusRequired"`
		DeviceThreatProtectionEnabled             bool   `json:"deviceThreatProtectionEnabled"`
		DeviceThreatProtectionRequiredSecurityLvl string `json:"deviceThreatProtectionRequiredSecurityLevel"`
		SecurityBlockJailbrokenDevices            bool   `json:"securityBlockJailbrokenDevices"`
		PasscodeRequired                          bool   `json:"passcodeRequired"`
		PasscodeMinimumLength                     int    `json:"passcodeMinimumLength"`
	} `json:"value"`
}

func checkWinComplianceHardware(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp compliancePoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceCompliancePolicies payload: %v", err)
	}
	for _, p := range resp.Value {
		if strings.Contains(strings.ToLower(p.ODataType), "windows10compliancepolicy") &&
			p.BitLockerEnabled && p.SecureBootEnabled && p.CodeIntegrityEnabled {
			return true, p.DisplayName, fmt.Sprintf("Windows compliance policy %q enforces BitLocker, Secure Boot and Code Integrity", p.DisplayName)
		}
	}
	return false, nil, "no Windows 10/11 compliance policy enforces BitLocker, Secure Boot and Code Integrity"
}

func checkWinComplianceDefender(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp compliancePoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceCompliancePolicies payload: %v", err)
	}
	for _, p := range resp.Value {
		if strings.Contains(strings.ToLower(p.ODataType), "windows10compliancepolicy") &&
			p.DefenderEnabled && p.RTPEnabled && p.FirewallEnabled && p.AntivirusRequired {
			return true, p.DisplayName, fmt.Sprintf("Windows compliance policy %q enforces Defender, RTP, antivirus and firewall", p.DisplayName)
		}
	}
	return false, nil, "no Windows 10/11 compliance policy enforces Defender, real-time protection, antivirus and firewall"
}

func checkWinComplianceThreatLevel(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp compliancePoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceCompliancePolicies payload: %v", err)
	}
	for _, p := range resp.Value {
		lvl := strings.ToLower(p.DeviceThreatProtectionRequiredSecurityLvl)
		if strings.Contains(strings.ToLower(p.ODataType), "windows10compliancepolicy") &&
			p.DeviceThreatProtectionEnabled && (lvl == "low" || lvl == "secured") {
			return true, lvl, fmt.Sprintf("Windows compliance policy %q enforces Defender for Endpoint threat level %q", p.DisplayName, lvl)
		}
	}
	return false, nil, "no Windows 10/11 compliance policy enforces Defender for Endpoint threat level low or secured"
}

func checkIOSComplianceBaseline(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp compliancePoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceCompliancePolicies payload: %v", err)
	}
	for _, p := range resp.Value {
		if strings.Contains(strings.ToLower(p.ODataType), "ioscompliancepolicy") &&
			p.SecurityBlockJailbrokenDevices && p.PasscodeRequired && p.PasscodeMinimumLength >= 6 {
			return true, p.DisplayName, fmt.Sprintf("iOS compliance policy %q blocks jailbroken devices and requires passcode length >= %d", p.DisplayName, p.PasscodeMinimumLength)
		}
	}
	return false, nil, "no iOS/iPadOS compliance policy blocks jailbroken devices with passcode length >= 6"
}

type configPoliciesResp struct {
	Value []struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		Description       string `json:"description"`
		Platforms         string `json:"platforms"`
		IsAssigned        bool   `json:"isAssigned"`
		TemplateReference struct {
			TemplateFamily string `json:"templateFamily"`
		} `json:"templateReference"`
	} `json:"value"`
}

func matchConfigPolicy(raw []byte, matchFn func(name, desc, platforms, templateFamily string) bool, label string) (bool, any, string) {
	var resp configPoliciesResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid configurationPolicies payload: %v", err)
	}
	for _, p := range resp.Value {
		if !p.IsAssigned {
			continue
		}
		if matchFn(
			strings.ToLower(p.Name),
			strings.ToLower(p.Description),
			strings.ToLower(p.Platforms),
			strings.ToLower(p.TemplateReference.TemplateFamily),
		) {
			return true, p.Name, fmt.Sprintf("assigned Intune policy %q satisfies %s", p.Name, label)
		}
	}
	return false, nil, fmt.Sprintf("no assigned Intune configuration policy found matching %s", label)
}

func checkCfgWindowsHardening(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return matchConfigPolicy(raw, func(name, desc, platforms, _ string) bool {
		return strings.Contains(platforms, "windows10") &&
			(strings.Contains(name, "windows") && (strings.Contains(name, "hardening") || strings.Contains(name, "blueprint") || strings.Contains(desc, "hardening")))
	}, "Windows hardening guidelines")
}

func checkCfgOfficeMacros(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return matchConfigPolicy(raw, func(name, desc, _, _ string) bool {
		combined := name + " " + desc
		return strings.Contains(combined, "macro") || (strings.Contains(combined, "office") && strings.Contains(combined, "hardening"))
	}, "Office macro hardening")
}

func checkCfgEdgeHardening(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return matchConfigPolicy(raw, func(name, desc, _, _ string) bool {
		combined := name + " " + desc
		return strings.Contains(combined, "edge") && (strings.Contains(combined, "hardening") || strings.Contains(combined, "baseline") || strings.Contains(combined, "blueprint"))
	}, "Microsoft Edge hardening")
}

func checkSecASRPolicy(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return matchConfigPolicy(raw, func(name, desc, _, family string) bool {
		combined := name + " " + desc
		return strings.Contains(family, "attacksurfacereduction") ||
			strings.Contains(combined, "attack surface reduction") ||
			strings.Contains(combined, "asr")
	}, "Attack Surface Reduction endpoint security policy")
}

func checkCfgIOSProfile(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ODataType   string `json:"@odata.type"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceConfigurations payload: %v", err)
	}
	for _, p := range resp.Value {
		if strings.Contains(strings.ToLower(p.ODataType), "ios") {
			return true, p.DisplayName, fmt.Sprintf("iOS/iPadOS device configuration profile %q is deployed", p.DisplayName)
		}
	}
	return false, nil, "no iOS/iPadOS device configuration profile found"
}

func checkSecBaselinesPresent(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			IsAssigned  bool   `json:"isAssigned"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid deviceManagement/intents payload: %v", err)
	}
	var assigned []string
	for _, intent := range resp.Value {
		if intent.IsAssigned {
			assigned = append(assigned, intent.DisplayName)
		}
	}
	if len(assigned) > 0 {
		return true, assigned, fmt.Sprintf("%d assigned Intune security baseline intent(s) active", len(assigned))
	}
	return false, assigned, "no assigned Intune security baseline intents found"
}

type managedAppProtectionsResp struct {
	Value []struct {
		DisplayName                       string `json:"displayName"`
		PinRequired                       bool   `json:"pinRequired"`
		AllowedOutboundDataTransferDests  string `json:"allowedOutboundDataTransferDestinations"`
		OrganizationalCredentialsRequired bool   `json:"organizationalCredentialsRequired"`
		MinimumPinLength                  int    `json:"minimumPinLength"`
		MaximumPinRetries                 int    `json:"maximumPinRetries"`
		DataBackupBlocked                 bool   `json:"dataBackupBlocked"`
	} `json:"value"`
}

func checkManagedAppProtection(raw []byte, platform string) (bool, any, string) {
	var resp managedAppProtectionsResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid %s managedAppProtections payload: %v", platform, err)
	}
	for _, p := range resp.Value {
		dest := strings.ToLower(p.AllowedOutboundDataTransferDests)
		if p.PinRequired && (dest == "managedapps" || dest == "none") && p.DataBackupBlocked {
			return true, p.DisplayName, fmt.Sprintf("%s app protection policy %q enforces PIN, blocks backup and restricts outbound data transfer (%s)", platform, p.DisplayName, dest)
		}
	}
	return false, nil, fmt.Sprintf("no %s managed app protection policy enforces PIN, blocks cloud backup and restricts outbound data transfer", platform)
}

func checkAppIOSProtection(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return checkManagedAppProtection(raw, "iOS")
}

func checkAppAndroidProtection(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	return checkManagedAppProtection(raw, "Android")
}
