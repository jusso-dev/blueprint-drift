package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/graph"
	"github.com/jusso-dev/blueprint-drift/src/snapshot"
)

// Event is a normalised read-only audit log event from Entra ID directory
// audits or the Microsoft Purview unified audit log.
type Event struct {
	Source     string    `json:"source"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Activity   string    `json:"activity"`
	Category   string    `json:"category"`
	Workload   string    `json:"workload,omitempty"`
	TargetName string    `json:"target_name,omitempty"`
}

// Correlator enriches drifted snapshot.DiffItem records with who changed a
// setting and when. Missing or inaccessible audit sources degrade gracefully.
type Correlator struct {
	Client        graph.Client
	UnifiedEvents []Event
}

// LoadUnifiedAuditFile parses a JSON export of Microsoft Purview unified audit
// events (either a JSON array or an object with a "value" array).
func LoadUnifiedAuditFile(path string) ([]Event, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read unified audit file %s: %w", path, err)
	}
	return ParseUnifiedAuditJSON(raw)
}

// ParseUnifiedAuditJSON decodes Microsoft Purview unified audit log records
// into normalised Event values.
func ParseUnifiedAuditJSON(raw []byte) ([]Event, error) {
	type rawUnified struct {
		CreationTime string `json:"CreationTime"`
		CreatedDT    string `json:"createdDateTime"`
		Operation    string `json:"Operation"`
		Activity     string `json:"operation"`
		Workload     string `json:"Workload"`
		Service      string `json:"service"`
		UserID       string `json:"UserId"`
		Actor        string `json:"userPrincipalName"`
		ObjectID     string `json:"ObjectId"`
		Target       string `json:"objectId"`
	}

	var rows []rawUnified
	if err := json.Unmarshal(raw, &rows); err != nil {
		var wrapper struct {
			Value []rawUnified `json:"value"`
		}
		if err2 := json.Unmarshal(raw, &wrapper); err2 != nil {
			return nil, fmt.Errorf("parse unified audit JSON: %w", err)
		}
		rows = wrapper.Value
	}

	events := make([]Event, 0, len(rows))
	for _, r := range rows {
		tsStr := firstNonEmpty(r.CreationTime, r.CreatedDT)
		ts, err := parseAuditTime(tsStr)
		if err != nil {
			continue
		}
		events = append(events, Event{
			Source:     "Unified Audit Log",
			Timestamp:  ts.UTC(),
			Actor:      firstNonEmpty(r.UserID, r.Actor, "unknown actor"),
			Activity:   firstNonEmpty(r.Operation, r.Activity),
			Category:   firstNonEmpty(r.Workload, r.Service),
			Workload:   firstNonEmpty(r.Workload, r.Service),
			TargetName: firstNonEmpty(r.ObjectID, r.Target),
		})
	}
	return events, nil
}

// Correlate looks up Entra directory audit logs and any configured unified
// audit events within the diff window [report.FromTime, report.ToTime] and
// annotates each drifted item with ChangedBy, ChangedAt and AuditNote.
// It never fails the diff when audit data is unavailable.
func (c *Correlator) Correlate(ctx context.Context, report *snapshot.DiffReport) {
	if report == nil || len(report.Items) == 0 {
		return
	}

	var (
		allEvents []Event
		warnings  []string
	)

	if c.Client != nil {
		entraEvents, err := c.fetchEntraDirectoryAudits(ctx, report.FromTime, report.ToTime)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Entra directory audit logs unavailable (%v)", err))
		} else {
			allEvents = append(allEvents, entraEvents...)
		}
	}

	if len(c.UnifiedEvents) > 0 {
		for _, ev := range c.UnifiedEvents {
			if withinWindow(ev.Timestamp, report.FromTime, report.ToTime) {
				allEvents = append(allEvents, ev)
			}
		}
	}

	// Sort newest-first so the most recent matching change wins.
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	for i := range report.Items {
		item := &report.Items[i]
		match := findBestMatch(item, allEvents)
		if match != nil {
			item.ChangedBy = match.Actor
			item.ChangedAt = match.Timestamp.UTC().Format(time.RFC3339)
			item.AuditNote = fmt.Sprintf("%s (%s)", match.Activity, match.Source)
			continue
		}
		if len(warnings) > 0 {
			item.AuditNote = strings.Join(warnings, "; ")
		} else {
			item.AuditNote = "no matching audit event found in snapshot window"
		}
	}
}

func (c *Correlator) fetchEntraDirectoryAudits(ctx context.Context, from, to time.Time) ([]Event, error) {
	endpoint := "/auditLogs/directoryAudits"
	if !from.IsZero() && !to.IsZero() {
		filter := fmt.Sprintf("activityDateTime ge %s and activityDateTime le %s",
			from.UTC().Format(time.RFC3339),
			to.UTC().Format(time.RFC3339),
		)
		endpoint = endpoint + "?$filter=" + url.QueryEscape(filter)
	}

	resp, err := c.Client.GetAllPages(ctx, "v1.0", endpoint)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Value []struct {
			ActivityDateTime    string `json:"activityDateTime"`
			ActivityDisplayName string `json:"activityDisplayName"`
			Category            string `json:"category"`
			InitiatedBy         struct {
				User *struct {
					UserPrincipalName string `json:"userPrincipalName"`
					DisplayName       string `json:"displayName"`
				} `json:"user"`
				App *struct {
					DisplayName string `json:"displayName"`
					AppID       string `json:"appId"`
				} `json:"app"`
			} `json:"initiatedBy"`
			TargetResources []struct {
				DisplayName string `json:"displayName"`
				Type        string `json:"type"`
			} `json:"targetResources"`
		} `json:"value"`
	}
	if err := json.Unmarshal(resp.RawBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse directoryAudits response: %w", err)
	}

	events := make([]Event, 0, len(parsed.Value))
	for _, row := range parsed.Value {
		ts, err := parseAuditTime(row.ActivityDateTime)
		if err != nil || !withinWindow(ts, from, to) {
			continue
		}
		actor := "unknown actor"
		if row.InitiatedBy.User != nil {
			actor = firstNonEmpty(row.InitiatedBy.User.UserPrincipalName, row.InitiatedBy.User.DisplayName, actor)
		} else if row.InitiatedBy.App != nil {
			appName := firstNonEmpty(row.InitiatedBy.App.DisplayName, row.InitiatedBy.App.AppID)
			actor = fmt.Sprintf("app:%s", appName)
		}
		target := ""
		if len(row.TargetResources) > 0 {
			target = firstNonEmpty(row.TargetResources[0].DisplayName, row.TargetResources[0].Type)
		}
		events = append(events, Event{
			Source:     "Entra directoryAudits",
			Timestamp:  ts.UTC(),
			Actor:      actor,
			Activity:   row.ActivityDisplayName,
			Category:   row.Category,
			TargetName: target,
		})
	}
	return events, nil
}

func findBestMatch(item *snapshot.DiffItem, events []Event) *Event {
	keywords := keywordsForSetting(item.SettingID)
	for i := range events {
		ev := &events[i]
		haystack := strings.ToLower(strings.Join([]string{
			ev.Activity,
			ev.Category,
			ev.Workload,
			ev.TargetName,
		}, " "))
		for _, kw := range keywords {
			if strings.Contains(haystack, kw) {
				return ev
			}
		}
	}
	return nil
}

func keywordsForSetting(settingID string) []string {
	id := strings.ToUpper(settingID)
	switch {
	case strings.HasPrefix(id, "ENTRA-CA-"):
		return []string{"conditional access", "named location", "conditionalaccess"}
	case strings.HasPrefix(id, "ENTRA-AUTH-"):
		return []string{"authentication method", "password protection", "lockout", "fido"}
	case strings.HasPrefix(id, "ENTRA-PIM-"):
		return []string{"role assignment", "eligible", "global administrator", "rolemanagement"}
	case strings.HasPrefix(id, "ENTRA-APP-"):
		return []string{"consent", "permission grant", "application"}
	case strings.HasPrefix(id, "ENTRA-PROP-"):
		return []string{"security default", "organization", "company information"}
	case strings.HasPrefix(id, "ENTRA-USER-"), strings.HasPrefix(id, "ENTRA-EXT-"):
		return []string{"authorization policy", "external collaboration", "cross-tenant", "guest"}
	case strings.HasPrefix(id, "ENTRA-DEV-"):
		return []string{"device registration", "laps", "device setting"}
	case strings.HasPrefix(id, "ENTRA-GRP-"):
		return []string{"group", "directory setting"}
	case strings.HasPrefix(id, "INTUNE-"):
		return []string{"compliance", "intune", "deviceconfiguration", "endpoint security", "app protection", "managedapp"}
	case strings.HasPrefix(id, "SPO-"):
		return []string{"sharepoint", "sharing", "set-spotenant", "syncclient"}
	case strings.HasPrefix(id, "EXO-"):
		return []string{"exchange", "transport", "domain", "remotedomain"}
	case strings.HasPrefix(id, "TEAMS-"):
		return []string{"teams", "federation", "meetingpolicy"}
	case strings.HasPrefix(id, "DEF-"):
		return []string{"defender", "securescore", "threat", "security"}
	default:
		return []string{"policy", "update"}
	}
}

func withinWindow(ts, from, to time.Time) bool {
	if !from.IsZero() && ts.Before(from) {
		return false
	}
	if !to.IsZero() && ts.After(to) {
		return false
	}
	return true
}

func parseAuditTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", raw)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
