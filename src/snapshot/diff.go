package snapshot

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/engine"
)

// ChangeKind classifies how a setting changed between two snapshots.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

// Direction classifies the security posture impact of a change.
type Direction string

const (
	DirectionRegressed  Direction = "regressed"
	DirectionRemediated Direction = "remediated"
	DirectionModified   Direction = "modified"
	DirectionAdded      Direction = "added"
	DirectionRemoved    Direction = "removed"
)

// DiffItem records a single added, removed or changed Blueprint setting.
type DiffItem struct {
	SettingID    string          `json:"setting_id"`
	Section      string          `json:"section"`
	Title        string          `json:"title"`
	Kind         ChangeKind      `json:"kind"`
	Direction    Direction       `json:"direction"`
	Severity     engine.Severity `json:"severity"`
	BeforeStatus engine.Status   `json:"before_status,omitempty"`
	AfterStatus  engine.Status   `json:"after_status,omitempty"`
	BeforeActual any             `json:"before_actual,omitempty"`
	AfterActual  any             `json:"after_actual,omitempty"`
	BeforeHash   string          `json:"before_hash,omitempty"`
	AfterHash    string          `json:"after_hash,omitempty"`
	ISMControls  []string        `json:"ism_controls,omitempty"`
	Summary      string          `json:"summary"`
	ChangedBy    string          `json:"changed_by,omitempty"`
	ChangedAt    string          `json:"changed_at,omitempty"`
	AuditNote    string          `json:"audit_note,omitempty"`
}

// DiffReport summarises all differences between two snapshots.
type DiffReport struct {
	FromRunID  string     `json:"from_run_id"`
	ToRunID    string     `json:"to_run_id"`
	TenantID   string     `json:"tenant_id"`
	FromTime   time.Time  `json:"from_time"`
	ToTime     time.Time  `json:"to_time"`
	Added      int        `json:"added"`
	Removed    int        `json:"removed"`
	Changed    int        `json:"changed"`
	Regressed  int        `json:"regressed"`
	Remediated int        `json:"remediated"`
	Items      []DiffItem `json:"items"`
}

// HasDrift reports whether any added, removed or changed items exist.
func (d *DiffReport) HasDrift() bool {
	return len(d.Items) > 0
}

// Diff compares two snapshots per setting ID and reports added, removed and
// changed settings sorted deterministically by SettingID.
func Diff(from, to *Snapshot) *DiffReport {
	report := &DiffReport{
		FromRunID: from.RunID,
		ToRunID:   to.RunID,
		TenantID:  to.TenantID,
		FromTime:  from.CapturedAt.UTC(),
		ToTime:    to.CapturedAt.UTC(),
	}

	keysMap := make(map[string]struct{}, len(from.Settings)+len(to.Settings))
	for id := range from.Settings {
		keysMap[id] = struct{}{}
	}
	for id := range to.Settings {
		keysMap[id] = struct{}{}
	}
	keys := make([]string, 0, len(keysMap))
	for id := range keysMap {
		keys = append(keys, id)
	}
	sort.Strings(keys)

	for _, id := range keys {
		before, inFrom := from.Settings[id]
		after, inTo := to.Settings[id]

		switch {
		case !inFrom && inTo:
			report.Added++
			report.Items = append(report.Items, DiffItem{
				SettingID:   id,
				Section:     after.Section,
				Title:       after.Title,
				Kind:        ChangeAdded,
				Direction:   DirectionAdded,
				Severity:    after.Severity,
				AfterStatus: after.Status,
				AfterActual: after.Actual,
				AfterHash:   after.ResponseSHA256,
				ISMControls: append([]string(nil), after.ISMControls...),
				Summary:     fmt.Sprintf("added with status %s", after.Status),
			})
		case inFrom && !inTo:
			report.Removed++
			report.Items = append(report.Items, DiffItem{
				SettingID:    id,
				Section:      before.Section,
				Title:        before.Title,
				Kind:         ChangeRemoved,
				Direction:    DirectionRemoved,
				Severity:     before.Severity,
				BeforeStatus: before.Status,
				BeforeActual: before.Actual,
				BeforeHash:   before.ResponseSHA256,
				ISMControls:  append([]string(nil), before.ISMControls...),
				Summary:      fmt.Sprintf("removed (previous status was %s)", before.Status),
			})
		default:
			statusChanged := before.Status != after.Status
			actualChanged := !engine.ValuesEqual(before.Actual, after.Actual)
			hashChanged := before.ResponseSHA256 != after.ResponseSHA256
			if !statusChanged && !actualChanged && !hashChanged {
				continue
			}

			report.Changed++
			dir := DirectionModified
			if before.Status == engine.StatusPass && (after.Status == engine.StatusFail || after.Status == engine.StatusError) {
				dir = DirectionRegressed
				report.Regressed++
			} else if (before.Status == engine.StatusFail || before.Status == engine.StatusError) && after.Status == engine.StatusPass {
				dir = DirectionRemediated
				report.Remediated++
			}

			var parts []string
			if statusChanged {
				parts = append(parts, fmt.Sprintf("status %s -> %s", before.Status, after.Status))
			}
			if actualChanged {
				parts = append(parts, fmt.Sprintf("actual %v -> %v", before.Actual, after.Actual))
			}
			if hashChanged && !statusChanged && !actualChanged {
				parts = append(parts, "raw Graph response hash changed")
			}

			report.Items = append(report.Items, DiffItem{
				SettingID:    id,
				Section:      after.Section,
				Title:        after.Title,
				Kind:         ChangeChanged,
				Direction:    dir,
				Severity:     after.Severity,
				BeforeStatus: before.Status,
				AfterStatus:  after.Status,
				BeforeActual: before.Actual,
				AfterActual:  after.Actual,
				BeforeHash:   before.ResponseSHA256,
				AfterHash:    after.ResponseSHA256,
				ISMControls:  append([]string(nil), after.ISMControls...),
				Summary:      strings.Join(parts, "; "),
			})
		}
	}

	return report
}

// RenderText formats a DiffReport for terminal output.
func RenderText(r *DiffReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Snapshot diff: %s (%s) -> %s (%s)\n",
		r.FromRunID, r.FromTime.Format(time.RFC3339),
		r.ToRunID, r.ToTime.Format(time.RFC3339))
	fmt.Fprintf(&b, "Summary: added=%d removed=%d changed=%d (regressed=%d remediated=%d)\n",
		r.Added, r.Removed, r.Changed, r.Regressed, r.Remediated)
	if len(r.Items) == 0 {
		b.WriteString("No drift detected between snapshots.\n")
		return b.String()
	}
	for _, item := range r.Items {
		line := fmt.Sprintf("- [%s/%s] %s (%s): %s", item.Kind, item.Direction, item.SettingID, item.Severity, item.Summary)
		if item.ChangedBy != "" {
			line += fmt.Sprintf(" | changed by %s at %s", item.ChangedBy, item.ChangedAt)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// RenderMarkdown formats a DiffReport as GitHub-flavoured Markdown suitable for
// drift issues and pull request comments.
func RenderMarkdown(r *DiffReport) string {
	var b strings.Builder
	b.WriteString("# Blueprint Drift Diff Report\n\n")
	fmt.Fprintf(&b, "- **From snapshot:** `%s` (`%s`)\n", r.FromRunID, r.FromTime.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **To snapshot:** `%s` (`%s`)\n", r.ToRunID, r.ToTime.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Tenant ID:** `%s`\n", r.TenantID)
	fmt.Fprintf(&b, "- **Summary:** added=%d, removed=%d, changed=%d (regressed=%d, remediated=%d)\n\n",
		r.Added, r.Removed, r.Changed, r.Regressed, r.Remediated)

	if len(r.Items) == 0 {
		b.WriteString("No drift detected between snapshots.\n")
		return b.String()
	}

	b.WriteString("| Setting ID | Kind | Direction | Severity | Before | After | Details | Audit Attribution |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, item := range r.Items {
		auditCell := "N/A"
		if item.ChangedBy != "" {
			auditCell = fmt.Sprintf("%s (%s)", item.ChangedBy, item.ChangedAt)
		} else if item.AuditNote != "" {
			auditCell = item.AuditNote
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s |\n",
			item.SettingID,
			item.Kind,
			item.Direction,
			item.Severity,
			item.BeforeStatus,
			item.AfterStatus,
			strings.ReplaceAll(item.Summary, "|", "\\|"),
			strings.ReplaceAll(auditCell, "|", "\\|"),
		)
	}
	return b.String()
}

// RenderJSON formats a DiffReport as indented JSON.
func RenderJSON(r *DiffReport) ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
