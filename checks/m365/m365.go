package m365

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/engine"
)

// Register registers Exchange Online, SharePoint Online and Microsoft Defender
// Graph check rules with the drift engine registry.
func Register(reg *engine.Registry) {
	reg.Register("exo_verified_domains_present", checkEXOVerifiedDomains)
	reg.Register("spo_domain_allowlist_configured", checkSPODomainAllowlist)
	reg.Register("defender_secure_score_present", checkDefenderSecureScore)
	reg.Register("defender_control_profiles_audited", checkDefenderControlProfiles)
	reg.Register("defender_mde_connector_active", checkDefenderMDEConnector)
	reg.Register("defender_endpoint_security_policies", checkDefenderEndpointSecurityPolicies)
	reg.Register("defender_incidents_visible", checkDefenderIncidentsVisible)
}

func checkEXOVerifiedDomains(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			IsVerified bool   `json:"isVerified"`
			IsDefault  bool   `json:"isDefault"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid domains payload: %v", err)
	}
	var verifiedCustom []string
	for _, d := range resp.Value {
		if d.IsVerified && !strings.HasSuffix(strings.ToLower(d.ID), ".onmicrosoft.com") {
			verifiedCustom = append(verifiedCustom, d.ID)
		}
	}
	if len(verifiedCustom) > 0 {
		return true, verifiedCustom, fmt.Sprintf("%d verified custom domain(s) inventoried for SPF/DKIM/DMARC review: %s", len(verifiedCustom), strings.Join(verifiedCustom, ", "))
	}
	return false, verifiedCustom, "no verified custom accepted domains found (only default onmicrosoft.com or unverified domains)"
}

func checkSPODomainAllowlist(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		SharingCapability            string   `json:"sharingCapability"`
		SharingDomainRestrictionMode string   `json:"sharingDomainRestrictionMode"`
		SharingAllowedDomainList     []string `json:"sharingAllowedDomainList"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid SharePoint settings payload: %v", err)
	}
	if strings.EqualFold(resp.SharingCapability, "disabled") {
		return true, "disabled", "external sharing is completely disabled across SharePoint Online"
	}
	actual := map[string]any{
		"sharingDomainRestrictionMode": resp.SharingDomainRestrictionMode,
		"sharingAllowedDomainList":     resp.SharingAllowedDomainList,
	}
	if strings.EqualFold(resp.SharingDomainRestrictionMode, "allowList") && len(resp.SharingAllowedDomainList) > 0 {
		return true, actual, fmt.Sprintf("SharePoint domain restriction is allowList with %d approved domain(s)", len(resp.SharingAllowedDomainList))
	}
	return false, actual, fmt.Sprintf("SharePoint domain restriction mode is %q with %d allow-listed domains; expected allowList with approved domains", resp.SharingDomainRestrictionMode, len(resp.SharingAllowedDomainList))
}

func checkDefenderSecureScore(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ID           string  `json:"id"`
			CurrentScore float64 `json:"currentScore"`
			MaxScore     float64 `json:"maxScore"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid secureScores payload: %v", err)
	}
	if len(resp.Value) > 0 && resp.Value[0].MaxScore > 0 {
		s := resp.Value[0]
		pct := (s.CurrentScore / s.MaxScore) * 100
		return true, map[string]any{"currentScore": s.CurrentScore, "maxScore": s.MaxScore}, fmt.Sprintf("Secure Score telemetry active (%.1f / %.1f, %.1f%%)", s.CurrentScore, s.MaxScore, pct)
	}
	return false, nil, "no Microsoft Secure Score telemetry returned"
}

func checkDefenderControlProfiles(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ID                  string `json:"id"`
			Title               string `json:"title"`
			ControlStateUpdates []struct {
				State   string `json:"state"`
				Comment string `json:"comment"`
			} `json:"controlStateUpdates"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid secureScoreControlProfiles payload: %v", err)
	}
	if len(resp.Value) == 0 {
		return false, 0, "no Secure Score control profiles returned"
	}
	var undocumentedIgnored []string
	for _, ctrl := range resp.Value {
		if len(ctrl.ControlStateUpdates) == 0 {
			continue
		}
		latest := ctrl.ControlStateUpdates[len(ctrl.ControlStateUpdates)-1]
		if strings.EqualFold(latest.State, "Ignored") && strings.TrimSpace(latest.Comment) == "" {
			undocumentedIgnored = append(undocumentedIgnored, ctrl.ID)
		}
	}
	if len(undocumentedIgnored) == 0 {
		return true, len(resp.Value), fmt.Sprintf("%d Secure Score control profile(s) audited with no undocumented ignored controls", len(resp.Value))
	}
	return false, undocumentedIgnored, fmt.Sprintf("%d Secure Score control(s) ignored without documented justification: %s", len(undocumentedIgnored), strings.Join(undocumentedIgnored, ", "))
}

func checkDefenderMDEConnector(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			ID                                string `json:"id"`
			PartnerState                      string `json:"partnerState"`
			WindowsDeviceBlockedOnMissingData bool   `json:"windowsDeviceBlockedOnMissingPartnerData"`
			WindowsEnabled                    bool   `json:"windowsEnabled"`
			AndroidEnabled                    bool   `json:"androidEnabled"`
			IOSEnabled                        bool   `json:"iosEnabled"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid mobileThreatDefenseConnectors payload: %v", err)
	}
	for _, c := range resp.Value {
		if strings.EqualFold(c.PartnerState, "enabled") && c.WindowsEnabled {
			return true, c.ID, fmt.Sprintf("Defender for Endpoint MTD connector %q is enabled for Windows", c.ID)
		}
	}
	return false, nil, "no enabled Defender for Endpoint mobileThreatDefenseConnector found for Windows"
}

func checkDefenderEndpointSecurityPolicies(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []struct {
			Name              string `json:"name"`
			IsAssigned        bool   `json:"isAssigned"`
			TemplateReference struct {
				TemplateFamily string `json:"templateFamily"`
			} `json:"templateReference"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid configurationPolicies payload: %v", err)
	}
	var hasAV, hasFirewall, hasEDR bool
	for _, p := range resp.Value {
		if !p.IsAssigned {
			continue
		}
		fam := strings.ToLower(p.TemplateReference.TemplateFamily)
		name := strings.ToLower(p.Name)
		if strings.Contains(fam, "antivirus") || strings.Contains(name, "antivirus") {
			hasAV = true
		}
		if strings.Contains(fam, "firewall") || strings.Contains(name, "firewall") {
			hasFirewall = true
		}
		if strings.Contains(fam, "endpointdetectionandresponse") || strings.Contains(name, "edr") {
			hasEDR = true
		}
	}
	actual := map[string]bool{"antivirus": hasAV, "firewall": hasFirewall, "edr": hasEDR}
	if hasAV && hasFirewall && hasEDR {
		return true, actual, "assigned Endpoint Security policies present for Antivirus, Firewall and EDR"
	}
	return false, actual, fmt.Sprintf("incomplete Defender Endpoint Security policy coverage: antivirus=%v firewall=%v edr=%v", hasAV, hasFirewall, hasEDR)
}

func checkDefenderIncidentsVisible(_ *blueprint.Setting, raw []byte) (bool, any, string) {
	var resp struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, nil, fmt.Sprintf("invalid security/incidents payload: %v", err)
	}
	if resp.Value != nil {
		return true, len(resp.Value), fmt.Sprintf("Defender XDR Graph incidents endpoint accessible (%d incident record(s) returned)", len(resp.Value))
	}
	return false, nil, "Defender XDR Graph incidents payload missing value array"
}
