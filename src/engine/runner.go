package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/blueprint"
	"github.com/jusso-dev/blueprint-drift/src/graph"
)

// RunResult is the complete output of a single drift evaluation run.
type RunResult struct {
	RunID            string        `json:"run_id"`
	TenantID         string        `json:"tenant_id"`
	BlueprintVersion string        `json:"blueprint_version"`
	GeneratedAt      time.Time     `json:"generated_at"`
	Summary          Summary       `json:"summary"`
	Results          []CheckResult `json:"results"`
}

// RuleFunc evaluates a Blueprint setting against a raw canonical Graph JSON payload.
type RuleFunc func(setting *blueprint.Setting, rawBody []byte) (pass bool, actual any, message string)

// Registry holds named rule evaluators registered by domain check packages.
type Registry struct {
	rules map[string]RuleFunc
}

// NewRegistry creates an empty rule evaluator registry.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]RuleFunc)}
}

// Register adds a named rule evaluator to the registry.
func (r *Registry) Register(name string, fn RuleFunc) {
	r.rules[name] = fn
}

// Get looks up a named rule evaluator.
func (r *Registry) Get(name string) (RuleFunc, bool) {
	fn, ok := r.rules[name]
	return fn, ok
}

// Runner executes Blueprint setting catalogs read-only against a graph.Client.
type Runner struct {
	Client   graph.Client
	Registry *Registry
	TenantID string
	Now      func() time.Time
}

// Run evaluates all settings in catalogs and returns a RunResult.
// Graph responses are cached per (version, endpoint) for the duration of the run.
func (r *Runner) Run(ctx context.Context, catalogs []*blueprint.Catalog) (*RunResult, error) {
	nowFn := r.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	ts := nowFn().UTC()

	tenantID := r.TenantID
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000000"
	}

	bpVersion := "unknown"
	if len(catalogs) > 0 && catalogs[0].BlueprintVersion != "" {
		bpVersion = catalogs[0].BlueprintVersion
	}

	cache := make(map[string]*graph.Response)
	errCache := make(map[string]error)
	var results []CheckResult

	for _, cat := range catalogs {
		for i := range cat.Settings {
			s := &cat.Settings[i]
			res := r.evaluateSetting(ctx, s, ts, cache, errCache)
			results = append(results, res)
		}
	}

	return &RunResult{
		RunID:            fmt.Sprintf("run-%s", ts.Format("20060102T150405Z")),
		TenantID:         tenantID,
		BlueprintVersion: bpVersion,
		GeneratedAt:      ts,
		Summary:          ComputeSummary(results),
		Results:          results,
	}, nil
}

func (r *Runner) evaluateSetting(
	ctx context.Context,
	s *blueprint.Setting,
	ts time.Time,
	cache map[string]*graph.Response,
	errCache map[string]error,
) CheckResult {
	base := CheckResult{
		SettingID:      s.ID,
		Section:        s.Section,
		Title:          s.Title,
		Description:    s.Description,
		Severity:       Severity(s.Severity),
		Expected:       s.Expected.Value,
		ISMControls:    append([]string(nil), s.ISMControls...),
		EssentialEight: append([]string(nil), s.EssentialEight...),
		References:     append([]string(nil), s.References...),
		EvaluatedAt:    ts,
	}

	if s.APISource.Kind == "manual" {
		base.Status = StatusManual
		base.Query = "manual"
		base.ManualReason = s.APISource.ManualReason
		base.Message = s.APISource.ManualReason
		if s.APISource.ManualGuidance != "" {
			base.Metadata = map[string]any{"manual_guidance": s.APISource.ManualGuidance}
		}
		return base
	}

	if r.Client == nil {
		base.Status = StatusError
		base.Query = fmt.Sprintf("GET /%s%s", s.APISource.Version, s.APISource.Endpoint)
		base.Message = "no Graph client configured"
		return base
	}

	cacheKey := s.APISource.Version + ":" + s.APISource.Endpoint
	resp, ok := cache[cacheKey]
	fetchErr, hadErr := errCache[cacheKey]
	if !ok && !hadErr {
		resp, fetchErr = r.Client.GetAllPages(ctx, s.APISource.Version, s.APISource.Endpoint)
		if fetchErr != nil {
			errCache[cacheKey] = fetchErr
		} else {
			cache[cacheKey] = resp
		}
	}

	if fetchErr != nil {
		base.Status = StatusError
		base.Query = fmt.Sprintf("GET /%s%s", s.APISource.Version, s.APISource.Endpoint)
		base.Message = fmt.Sprintf("Graph read error: %v", fetchErr)
		return base
	}

	base.Query = resp.Query
	base.ResponseSHA256 = resp.SHA256

	if s.Expected.Rule != "" {
		if r.Registry == nil {
			base.Status = StatusError
			base.Message = fmt.Sprintf("no rule registry configured for rule %q", s.Expected.Rule)
			return base
		}
		fn, found := r.Registry.Get(s.Expected.Rule)
		if !found {
			base.Status = StatusError
			base.Message = fmt.Sprintf("rule evaluator %q is not registered", s.Expected.Rule)
			return base
		}
		pass, actual, msg := fn(s, resp.RawBody)
		base.Actual = actual
		base.Message = msg
		if pass {
			base.Status = StatusPass
		} else {
			base.Status = StatusFail
		}
		return base
	}

	pass, actual, msg, evalErr := evaluateDeclarative(s, resp.RawBody)
	if evalErr != nil {
		base.Status = StatusError
		base.Message = evalErr.Error()
		return base
	}
	base.Actual = actual
	base.Message = msg
	if pass {
		base.Status = StatusPass
	} else {
		base.Status = StatusFail
	}
	return base
}

func evaluateDeclarative(s *blueprint.Setting, rawBody []byte) (bool, any, string, error) {
	var parsed any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return false, nil, "", fmt.Errorf("parse JSON response: %w", err)
	}

	actual, found := ExtractPath(parsed, s.Expected.Path)
	if !found {
		return false, nil, fmt.Sprintf("property path %q not found in response", s.Expected.Path), nil
	}

	switch s.Expected.Operator {
	case "equals":
		ok := ValuesEqual(actual, s.Expected.Value)
		if ok {
			return true, actual, fmt.Sprintf("%s equals expected value %v", s.Expected.Path, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s is %v; expected %v", s.Expected.Path, actual, s.Expected.Value), nil

	case "not_equals":
		ok := !ValuesEqual(actual, s.Expected.Value)
		if ok {
			return true, actual, fmt.Sprintf("%s (%v) differs from disallowed value %v", s.Expected.Path, actual, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s equals disallowed value %v", s.Expected.Path, s.Expected.Value), nil

	case "in":
		list, ok := toSlice(s.Expected.Value)
		if !ok {
			return false, actual, "", fmt.Errorf("expected.value for operator \"in\" must be a list")
		}
		for _, item := range list {
			if ValuesEqual(actual, item) {
				return true, actual, fmt.Sprintf("%s (%v) is in allowed set %v", s.Expected.Path, actual, list), nil
			}
		}
		return false, actual, fmt.Sprintf("%s is %v; expected one of %v", s.Expected.Path, actual, list), nil

	case "lte":
		a, aOk := toFloat(actual)
		e, eOk := toFloat(s.Expected.Value)
		if !aOk || !eOk {
			return false, actual, fmt.Sprintf("non-numeric comparison for %s (%v <= %v)", s.Expected.Path, actual, s.Expected.Value), nil
		}
		if a <= e {
			return true, actual, fmt.Sprintf("%s (%v) is <= %v", s.Expected.Path, actual, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s is %v; expected <= %v", s.Expected.Path, actual, s.Expected.Value), nil

	case "gte":
		a, aOk := toFloat(actual)
		e, eOk := toFloat(s.Expected.Value)
		if !aOk || !eOk {
			return false, actual, fmt.Sprintf("non-numeric comparison for %s (%v >= %v)", s.Expected.Path, actual, s.Expected.Value), nil
		}
		if a >= e {
			return true, actual, fmt.Sprintf("%s (%v) is >= %v", s.Expected.Path, actual, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s is %v; expected >= %v", s.Expected.Path, actual, s.Expected.Value), nil

	case "contains":
		if slice, ok := toSlice(actual); ok {
			for _, item := range slice {
				if ValuesEqual(item, s.Expected.Value) {
					return true, actual, fmt.Sprintf("%s contains %v", s.Expected.Path, s.Expected.Value), nil
				}
			}
			return false, actual, fmt.Sprintf("%s does not contain %v", s.Expected.Path, s.Expected.Value), nil
		}
		if str, ok := actual.(string); ok {
			if strings.Contains(str, fmt.Sprint(s.Expected.Value)) {
				return true, actual, fmt.Sprintf("%s contains %q", s.Expected.Path, s.Expected.Value), nil
			}
			return false, actual, fmt.Sprintf("%s (%q) does not contain %q", s.Expected.Path, str, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s is neither string nor array", s.Expected.Path), nil

	case "not_contains":
		if slice, ok := toSlice(actual); ok {
			for _, item := range slice {
				if ValuesEqual(item, s.Expected.Value) {
					return false, actual, fmt.Sprintf("%s contains disallowed value %v", s.Expected.Path, s.Expected.Value), nil
				}
			}
			return true, actual, fmt.Sprintf("%s does not contain %v", s.Expected.Path, s.Expected.Value), nil
		}
		if str, ok := actual.(string); ok {
			if strings.Contains(str, fmt.Sprint(s.Expected.Value)) {
				return false, actual, fmt.Sprintf("%s contains disallowed substring %q", s.Expected.Path, s.Expected.Value), nil
			}
			return true, actual, fmt.Sprintf("%s does not contain %q", s.Expected.Path, s.Expected.Value), nil
		}
		return false, actual, fmt.Sprintf("%s is neither string nor array", s.Expected.Path), nil

	default:
		return false, actual, "", fmt.Errorf("operator %q requires a registered expected.rule", s.Expected.Operator)
	}
}

// ExtractPath traverses a dotted property path (for example
// "defaultUserRolePermissions.allowedToCreateApps") through decoded JSON maps.
func ExtractPath(root any, path string) (any, bool) {
	if strings.TrimSpace(path) == "" {
		return root, true
	}
	curr := root
	for _, seg := range strings.Split(path, ".") {
		m, ok := curr.(map[string]any)
		if !ok {
			return nil, false
		}
		val, exists := m[seg]
		if !exists {
			return nil, false
		}
		curr = val
	}
	return curr, true
}

// ValuesEqual compares two decoded YAML/JSON values with numeric and string
// normalisation (e.g. YAML int 30 vs JSON float64 30).
func ValuesEqual(a, b any) bool {
	if af, aOk := toFloat(a); aOk {
		if bf, bOk := toFloat(b); bOk {
			return math.Abs(af-bf) < 1e-9
		}
	}
	if as, aOk := a.(string); aOk {
		if bs, bOk := b.(string); bOk {
			return strings.EqualFold(as, bs)
		}
	}
	return reflect.DeepEqual(a, b)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	default:
		return 0, false
	}
}

func toSlice(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	if s, ok := v.([]any); ok {
		return s, true
	}
	if ss, ok := v.([]string); ok {
		out := make([]any, len(ss))
		for i, item := range ss {
			out[i] = item
		}
		return out, true
	}
	return nil, false
}
