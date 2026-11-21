package engine

import (
	"fmt"
	"time"
)

// Status represents the evaluation outcome for a single Blueprint setting.
type Status string

const (
	StatusPass   Status = "pass"
	StatusFail   Status = "fail"
	StatusManual Status = "manual"
	StatusError  Status = "error"
)

// Severity classifies the risk impact of a setting deviating from the Blueprint.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// CheckResult records the evaluated outcome and provenance for a single setting.
type CheckResult struct {
	SettingID      string         `json:"setting_id"`
	Section        string         `json:"section"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Status         Status         `json:"status"`
	Severity       Severity       `json:"severity"`
	Expected       any            `json:"expected"`
	Actual         any            `json:"actual,omitempty"`
	Message        string         `json:"message"`
	Query          string         `json:"query"`
	ResponseSHA256 string         `json:"response_sha256,omitempty"`
	ISMControls    []string       `json:"ism_controls,omitempty"`
	EssentialEight []string       `json:"essential_eight,omitempty"`
	References     []string       `json:"references,omitempty"`
	ManualReason   string         `json:"manual_reason,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	EvaluatedAt    time.Time      `json:"evaluated_at"`
}

// Summary aggregates check counts across a single drift run.
type Summary struct {
	Total  int `json:"total"`
	Pass   int `json:"pass"`
	Fail   int `json:"fail"`
	Manual int `json:"manual"`
	Error  int `json:"error"`
}

// ComputeSummary calculates result counts from a slice of CheckResult items.
func ComputeSummary(results []CheckResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusManual:
			s.Manual++
		case StatusError:
			s.Error++
		}
	}
	return s
}

// ValidateStatus checks whether a Status value is one of the known constants.
func ValidateStatus(st Status) error {
	switch st {
	case StatusPass, StatusFail, StatusManual, StatusError:
		return nil
	default:
		return fmt.Errorf("unknown check status %q", st)
	}
}
