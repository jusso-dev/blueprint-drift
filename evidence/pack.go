package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/engine"
)

// DisclaimerText is included in every generated IRAP evidence artefact.
const DisclaimerText = "Independent community project. Not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft."

// Manifest records reproducible SHA-256 digests for every file in an evidence pack.
type Manifest struct {
	RunID            string            `json:"run_id"`
	TenantID         string            `json:"tenant_id"`
	BlueprintVersion string            `json:"blueprint_version"`
	GeneratedAt      time.Time         `json:"generated_at"`
	Disclaimer       string            `json:"disclaimer"`
	Summary          engine.Summary    `json:"summary"`
	Artefacts        map[string]string `json:"artefacts_sha256"`
}

// ISMSummaryEntry aggregates check outcomes for a single ISM control ID.
type ISMSummaryEntry struct {
	ControlID string   `json:"control_id"`
	Pass      int      `json:"pass"`
	Fail      int      `json:"fail"`
	Manual    int      `json:"manual"`
	Error     int      `json:"error"`
	Settings  []string `json:"settings"`
}

// JSONReport is the structured JSON evidence pack document.
type JSONReport struct {
	RunID            string               `json:"run_id"`
	TenantID         string               `json:"tenant_id"`
	BlueprintVersion string               `json:"blueprint_version"`
	GeneratedAt      time.Time            `json:"generated_at"`
	Disclaimer       string               `json:"disclaimer"`
	Summary          engine.Summary       `json:"summary"`
	ISMControlMap    []ISMSummaryEntry    `json:"ism_control_summary"`
	ManualItems      []engine.CheckResult `json:"manual_items"`
	Results          []engine.CheckResult `json:"results"`
}

// WritePack generates Markdown, HTML, CSV, JSON and a SHA-256 manifest in outDir.
func WritePack(run *engine.RunResult, outDir string) (*Manifest, error) {
	if run == nil {
		return nil, fmt.Errorf("run result is nil")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory %s: %w", outDir, err)
	}

	mdBytes, err := RenderMarkdown(run)
	if err != nil {
		return nil, fmt.Errorf("render markdown: %w", err)
	}
	htmlBytes, err := RenderHTML(run)
	if err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}
	csvBytes, err := RenderCSV(run)
	if err != nil {
		return nil, fmt.Errorf("render csv: %w", err)
	}
	jsonBytes, err := RenderJSON(run)
	if err != nil {
		return nil, fmt.Errorf("render json: %w", err)
	}

	files := map[string][]byte{
		"evidence-report.md":   mdBytes,
		"evidence-report.html": htmlBytes,
		"evidence-report.csv":  csvBytes,
		"evidence-report.json": jsonBytes,
	}

	manifest := &Manifest{
		RunID:            run.RunID,
		TenantID:         run.TenantID,
		BlueprintVersion: run.BlueprintVersion,
		GeneratedAt:      run.GeneratedAt.UTC(),
		Disclaimer:       DisclaimerText,
		Summary:          run.Summary,
		Artefacts:        make(map[string]string, len(files)),
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		data := files[name]
		if err := os.WriteFile(filepath.Join(outDir, name), data, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}
		manifest.Artefacts[name] = sha256Hex(data)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(filepath.Join(outDir, "evidence-manifest.json"), manifestBytes, 0o644); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	return manifest, nil
}

// BuildISMSummary groups results by sorted ISM control identifier.
func BuildISMSummary(results []engine.CheckResult) []ISMSummaryEntry {
	byCtrl := make(map[string]*ISMSummaryEntry)
	for _, r := range results {
		for _, ctrl := range r.ISMControls {
			entry, ok := byCtrl[ctrl]
			if !ok {
				entry = &ISMSummaryEntry{ControlID: ctrl}
				byCtrl[ctrl] = entry
			}
			entry.Settings = append(entry.Settings, r.SettingID)
			switch r.Status {
			case engine.StatusPass:
				entry.Pass++
			case engine.StatusFail:
				entry.Fail++
			case engine.StatusManual:
				entry.Manual++
			case engine.StatusError:
				entry.Error++
			}
		}
	}

	keys := make([]string, 0, len(byCtrl))
	for k := range byCtrl {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ISMSummaryEntry, 0, len(keys))
	for _, k := range keys {
		e := byCtrl[k]
		sort.Strings(e.Settings)
		out = append(out, *e)
	}
	return out
}

// ManualResults filters results down to items requiring manual assessor review.
func ManualResults(results []engine.CheckResult) []engine.CheckResult {
	var out []engine.CheckResult
	for _, r := range results {
		if r.Status == engine.StatusManual {
			out = append(out, r)
		}
	}
	return out
}

// RenderJSON produces a deterministic, indented JSON evidence report.
func RenderJSON(run *engine.RunResult) ([]byte, error) {
	doc := JSONReport{
		RunID:            run.RunID,
		TenantID:         run.TenantID,
		BlueprintVersion: run.BlueprintVersion,
		GeneratedAt:      run.GeneratedAt.UTC(),
		Disclaimer:       DisclaimerText,
		Summary:          run.Summary,
		ISMControlMap:    BuildISMSummary(run.Results),
		ManualItems:      ManualResults(run.Results),
		Results:          run.Results,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// RenderCSV produces a flat CSV table suitable for IRAP workbooks and spreadsheets.
func RenderCSV(run *engine.RunResult) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	header := []string{
		"run_id",
		"timestamp_utc",
		"tenant_id",
		"blueprint_version",
		"setting_id",
		"section",
		"title",
		"status",
		"severity",
		"query",
		"response_sha256",
		"ism_controls",
		"essential_eight",
		"expected",
		"actual",
		"message",
		"manual_reason",
	}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	ts := run.GeneratedAt.UTC().Format(time.RFC3339)
	for _, r := range run.Results {
		row := []string{
			run.RunID,
			ts,
			run.TenantID,
			run.BlueprintVersion,
			r.SettingID,
			r.Section,
			r.Title,
			string(r.Status),
			string(r.Severity),
			r.Query,
			r.ResponseSHA256,
			strings.Join(r.ISMControls, ";"),
			strings.Join(r.EssentialEight, ";"),
			formatValue(r.Expected),
			formatValue(r.Actual),
			r.Message,
			r.ManualReason,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderMarkdown produces a GitHub-flavoured Markdown evidence report.
func RenderMarkdown(run *engine.RunResult) ([]byte, error) {
	var b strings.Builder
	ts := run.GeneratedAt.UTC().Format(time.RFC3339)
	ismSummary := BuildISMSummary(run.Results)
	manualItems := ManualResults(run.Results)

	b.WriteString("# IRAP Evidence Pack: ASD Blueprint for Secure Cloud Drift Assessment\n\n")
	b.WriteString("> **Disclaimer:** " + DisclaimerText + "\n\n")
	b.WriteString("## Run metadata\n\n")
	b.WriteString(fmt.Sprintf("- **Run ID:** `%s`\n", run.RunID))
	b.WriteString(fmt.Sprintf("- **Timestamp (UTC):** `%s`\n", ts))
	b.WriteString(fmt.Sprintf("- **Tenant ID:** `%s`\n", run.TenantID))
	b.WriteString(fmt.Sprintf("- **Blueprint version:** `%s`\n\n", run.BlueprintVersion))

	b.WriteString("## Executive summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("| --- | ---: |\n")
	b.WriteString(fmt.Sprintf("| Total settings evaluated | %d |\n", run.Summary.Total))
	b.WriteString(fmt.Sprintf("| Pass | %d |\n", run.Summary.Pass))
	b.WriteString(fmt.Sprintf("| Fail (drift detected) | %d |\n", run.Summary.Fail))
	b.WriteString(fmt.Sprintf("| Manual review required | %d |\n", run.Summary.Manual))
	b.WriteString(fmt.Sprintf("| Error | %d |\n\n", run.Summary.Error))

	b.WriteString("## Setting evaluation results\n\n")
	b.WriteString("| Setting ID | Section | Status | Severity | ISM Controls | Query | Response SHA-256 | Finding |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range run.Results {
		hashCell := "N/A"
		if r.ResponseSHA256 != "" {
			hashCell = "`" + r.ResponseSHA256 + "`"
		}
		b.WriteString(fmt.Sprintf(
			"| `%s` | %s | `%s` | `%s` | %s | `%s` | %s | %s |\n",
			r.SettingID,
			escapeMDCell(r.Section),
			r.Status,
			r.Severity,
			strings.Join(r.ISMControls, ", "),
			escapeMDCell(r.Query),
			hashCell,
			escapeMDCell(r.Message),
		))
	}
	b.WriteString("\n")

	b.WriteString("## ISM control mapping summary\n\n")
	b.WriteString("| ISM Control | Pass | Fail | Manual | Error | Settings |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: | --- |\n")
	for _, entry := range ismSummary {
		b.WriteString(fmt.Sprintf(
			"| `%s` | %d | %d | %d | %d | %s |\n",
			entry.ControlID,
			entry.Pass,
			entry.Fail,
			entry.Manual,
			entry.Error,
			strings.Join(entry.Settings, ", "),
		))
	}
	b.WriteString("\n")

	b.WriteString("## Manual items checklist for IRAP assessor\n\n")
	if len(manualItems) == 0 {
		b.WriteString("No manual items were included in this run.\n")
	} else {
		b.WriteString(fmt.Sprintf("The following %d setting(s) have no read-only Microsoft Graph API and require manual or PowerShell verification:\n\n", len(manualItems)))
		for _, m := range manualItems {
			b.WriteString(fmt.Sprintf("### `%s`: %s\n\n", m.SettingID, m.Title))
			b.WriteString(fmt.Sprintf("- **Section:** %s\n", m.Section))
			b.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", m.Severity))
			b.WriteString(fmt.Sprintf("- **ISM Controls:** %s\n", strings.Join(m.ISMControls, ", ")))
			b.WriteString(fmt.Sprintf("- **Reason manual:** %s\n", m.ManualReason))
			if guidance, ok := m.Metadata["manual_guidance"].(string); ok && guidance != "" {
				b.WriteString(fmt.Sprintf("- **Verification guidance:** %s\n", guidance))
			}
			b.WriteString("\n")
		}
	}

	return []byte(b.String()), nil
}

type htmlTemplateData struct {
	Run         *engine.RunResult
	Timestamp   string
	Disclaimer  string
	ISMSummary  []ISMSummaryEntry
	ManualItems []engine.CheckResult
}

var htmlReportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"join": strings.Join,
	"guidance": func(r engine.CheckResult) string {
		if r.Metadata == nil {
			return ""
		}
		if g, ok := r.Metadata["manual_guidance"].(string); ok {
			return g
		}
		return ""
	},
}).Parse(`<!DOCTYPE html>
<html lang="en-AU">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IRAP Evidence Pack - {{.Run.RunID}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1b2430; background: #f7f9fc; margin: 0; padding: 24px; line-height: 1.5; }
  .container { max-width: 1280px; margin: 0 auto; background: #ffffff; border: 1px solid #d9e2ec; border-radius: 8px; padding: 28px; }
  h1, h2, h3 { color: #102a43; margin-top: 1.4em; }
  h1 { margin-top: 0; border-bottom: 2px solid #d9e2ec; padding-bottom: 10px; }
  .disclaimer { background: #f0f4f8; border-left: 4px solid #486581; padding: 12px 16px; margin: 16px 0; font-size: 0.92rem; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 16px 0; }
  .card { background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 6px; padding: 12px 16px; }
  .card-label { font-size: 0.8rem; text-transform: uppercase; color: #627d98; letter-spacing: 0.04em; }
  .card-value { font-size: 1.2rem; font-weight: 600; margin-top: 4px; word-break: break-all; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 16px 0 24px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.88rem; }
  th, td { border: 1px solid #d9e2ec; padding: 8px 10px; text-align: left; vertical-align: top; }
  th { background: #f0f4f8; color: #102a43; font-weight: 600; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; background: #f0f4f8; padding: 1px 4px; border-radius: 3px; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.78rem; font-weight: 600; text-transform: uppercase; }
  .badge-pass { background: #e3f9e5; color: #1f7a38; }
  .badge-fail { background: #ffe3e3; color: #ab091e; }
  .badge-manual { background: #fff3c4; color: #8d2b0b; }
  .badge-error { background: #e6e6ff; color: #3f2b96; }
  .manual-card { border: 1px solid #f0b429; background: #fffdf5; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px; }
</style>
</head>
<body>
<div class="container">
  <h1>IRAP Evidence Pack: ASD Blueprint for Secure Cloud Drift Assessment</h1>
  <div class="disclaimer"><strong>Disclaimer:</strong> {{.Disclaimer}}</div>

  <div class="meta">
    <div class="card"><div class="card-label">Run ID</div><div class="card-value"><code>{{.Run.RunID}}</code></div></div>
    <div class="card"><div class="card-label">Timestamp (UTC)</div><div class="card-value"><code>{{.Timestamp}}</code></div></div>
    <div class="card"><div class="card-label">Tenant ID</div><div class="card-value"><code>{{.Run.TenantID}}</code></div></div>
    <div class="card"><div class="card-label">Blueprint Version</div><div class="card-value"><code>{{.Run.BlueprintVersion}}</code></div></div>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="card"><div class="card-label">Total</div><div class="card-value">{{.Run.Summary.Total}}</div></div>
    <div class="card"><div class="card-label">Pass</div><div class="card-value">{{.Run.Summary.Pass}}</div></div>
    <div class="card"><div class="card-label">Fail</div><div class="card-value">{{.Run.Summary.Fail}}</div></div>
    <div class="card"><div class="card-label">Manual</div><div class="card-value">{{.Run.Summary.Manual}}</div></div>
    <div class="card"><div class="card-label">Error</div><div class="card-value">{{.Run.Summary.Error}}</div></div>
  </div>

  <h2>Setting Evaluation Results</h2>
  <table>
    <thead>
      <tr>
        <th>Setting ID</th>
        <th>Section</th>
        <th>Status</th>
        <th>Severity</th>
        <th>ISM Controls</th>
        <th>Read-Only Query</th>
        <th>Response SHA-256</th>
        <th>Finding</th>
      </tr>
    </thead>
    <tbody>
      {{range .Run.Results}}
      <tr>
        <td><code>{{.SettingID}}</code></td>
        <td>{{.Section}}</td>
        <td><span class="badge badge-{{.Status}}">{{.Status}}</span></td>
        <td><code>{{.Severity}}</code></td>
        <td>{{join .ISMControls ", "}}</td>
        <td><code>{{.Query}}</code></td>
        <td>{{if .ResponseSHA256}}<code>{{.ResponseSHA256}}</code>{{else}}N/A{{end}}</td>
        <td>{{.Message}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  <h2>ISM Control Mapping Summary</h2>
  <table>
    <thead>
      <tr>
        <th>ISM Control</th>
        <th>Pass</th>
        <th>Fail</th>
        <th>Manual</th>
        <th>Error</th>
        <th>Settings</th>
      </tr>
    </thead>
    <tbody>
      {{range .ISMSummary}}
      <tr>
        <td><code>{{.ControlID}}</code></td>
        <td>{{.Pass}}</td>
        <td>{{.Fail}}</td>
        <td>{{.Manual}}</td>
        <td>{{.Error}}</td>
        <td>{{join .Settings ", "}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  <h2>Manual Items Checklist for IRAP Assessor</h2>
  {{if .ManualItems}}
    {{range .ManualItems}}
    <div class="manual-card">
      <h3><code>{{.SettingID}}</code>: {{.Title}}</h3>
      <p><strong>Section:</strong> {{.Section}} | <strong>Severity:</strong> <code>{{.Severity}}</code> | <strong>ISM Controls:</strong> {{join .ISMControls ", "}}</p>
      <p><strong>Reason manual:</strong> {{.ManualReason}}</p>
      {{if guidance .}}<p><strong>Verification guidance:</strong> {{guidance .}}</p>{{end}}
    </div>
    {{end}}
  {{else}}
    <p>No manual items were included in this run.</p>
  {{end}}
</div>
</body>
</html>
`))

// RenderHTML produces a standalone, offline-ready HTML evidence report.
func RenderHTML(run *engine.RunResult) ([]byte, error) {
	var buf bytes.Buffer
	data := htmlTemplateData{
		Run:         run,
		Timestamp:   run.GeneratedAt.UTC().Format(time.RFC3339),
		Disclaimer:  DisclaimerText,
		ISMSummary:  BuildISMSummary(run.Results),
		ManualItems: ManualResults(run.Results),
	}
	if err := htmlReportTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func escapeMDCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func formatValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprint(val)
		}
		return string(b)
	}
}
