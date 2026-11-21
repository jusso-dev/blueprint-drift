package blueprint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog represents a machine-readable Blueprint setting catalog file.
type Catalog struct {
	SchemaVersion    string    `yaml:"schema_version" json:"schema_version"`
	BlueprintVersion string    `yaml:"blueprint_version" json:"blueprint_version"`
	Domain           string    `yaml:"domain" json:"domain"`
	Settings         []Setting `yaml:"settings" json:"settings"`
}

// Setting defines a single Blueprint configuration check.
type Setting struct {
	ID             string    `yaml:"id" json:"id"`
	Section        string    `yaml:"section" json:"section"`
	Title          string    `yaml:"title" json:"title"`
	Description    string    `yaml:"description" json:"description"`
	Severity       string    `yaml:"severity" json:"severity"`
	Expected       Expected  `yaml:"expected" json:"expected"`
	APISource      APISource `yaml:"api_source" json:"api_source"`
	ISMControls    []string  `yaml:"ism_controls" json:"ism_controls"`
	EssentialEight []string  `yaml:"essential_eight,omitempty" json:"essential_eight,omitempty"`
	References     []string  `yaml:"references" json:"references"`
}

// Expected defines the desired baseline state or named evaluation rule.
type Expected struct {
	Operator string `yaml:"operator" json:"operator"`
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	Value    any    `yaml:"value,omitempty" json:"value,omitempty"`
	Rule     string `yaml:"rule,omitempty" json:"rule,omitempty"`
}

// APISource describes how a setting is read from Microsoft Graph or marked manual.
type APISource struct {
	Kind              string   `yaml:"kind" json:"kind"`
	Version           string   `yaml:"version,omitempty" json:"version,omitempty"`
	Method            string   `yaml:"method,omitempty" json:"method,omitempty"`
	Endpoint          string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Permissions       []string `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	JunctionOperation string   `yaml:"junction_operation,omitempty" json:"junction_operation,omitempty"`
	ManualReason      string   `yaml:"manual_reason,omitempty" json:"manual_reason,omitempty"`
	ManualGuidance    string   `yaml:"manual_guidance,omitempty" json:"manual_guidance,omitempty"`
}

var (
	reSemver     = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	reSettingID  = regexp.MustCompile(`^[A-Z]+-[A-Z0-9]+-[0-9]{3}$`)
	reISMControl = regexp.MustCompile(`^ISM-[0-9]{4}$`)

	validDomains = map[string]bool{
		"entra-id":          true,
		"intune":            true,
		"exchange-online":   true,
		"sharepoint-online": true,
		"teams":             true,
		"defender":          true,
	}

	validSeverities = map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	validOperators = map[string]bool{
		"equals":        true,
		"not_equals":    true,
		"contains":      true,
		"not_contains":  true,
		"lte":           true,
		"gte":           true,
		"in":            true,
		"policy_exists": true,
		"manual":        true,
	}

	validEssentialEight = map[string]bool{
		"Application control":                       true,
		"Patch applications":                        true,
		"Configure Microsoft Office macro settings": true,
		"User application hardening":                true,
		"Restrict administrative privileges":        true,
		"Patch operating systems":                   true,
		"Multi-factor authentication":               true,
		"Regular backups":                           true,
	}
)

// LoadFile parses and validates a single Blueprint YAML catalog file.
func LoadFile(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cat Catalog
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cat); err != nil {
		return nil, fmt.Errorf("parse YAML %s: %w", path, err)
	}
	if err := ValidateCatalog(&cat); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &cat, nil
}

// LoadDir loads and validates all .yaml/.yml catalog files in dir and enforces
// globally unique setting IDs across files.
func LoadDir(dir string) ([]*Catalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no YAML catalog files found in %s", dir)
	}

	seenIDs := make(map[string]string)
	catalogs := make([]*Catalog, 0, len(files))
	for _, f := range files {
		cat, err := LoadFile(f)
		if err != nil {
			return nil, err
		}
		for _, s := range cat.Settings {
			if prev, exists := seenIDs[s.ID]; exists {
				return nil, fmt.Errorf("duplicate setting id %q in %s (already defined in %s)", s.ID, f, prev)
			}
			seenIDs[s.ID] = f
		}
		catalogs = append(catalogs, cat)
	}
	return catalogs, nil
}

// ValidateCatalog verifies a parsed Catalog matches blueprint/schema/settings.schema.json.
func ValidateCatalog(cat *Catalog) error {
	if cat.SchemaVersion != "1.0" {
		return fmt.Errorf("schema_version must be \"1.0\", got %q", cat.SchemaVersion)
	}
	if !reSemver.MatchString(cat.BlueprintVersion) {
		return fmt.Errorf("blueprint_version %q must match vX.Y.Z", cat.BlueprintVersion)
	}
	if !validDomains[cat.Domain] {
		return fmt.Errorf("unsupported domain %q", cat.Domain)
	}
	if len(cat.Settings) == 0 {
		return fmt.Errorf("settings must contain at least one entry")
	}

	seen := make(map[string]bool, len(cat.Settings))
	for i, s := range cat.Settings {
		if err := ValidateSetting(&s); err != nil {
			return fmt.Errorf("settings[%d] (%s): %w", i, s.ID, err)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate setting id %q within catalog", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}

// ValidateSetting validates a single Blueprint setting definition.
func ValidateSetting(s *Setting) error {
	if !reSettingID.MatchString(s.ID) {
		return fmt.Errorf("id %q must match ^[A-Z]+-[A-Z0-9]+-[0-9]{3}$", s.ID)
	}
	if strings.TrimSpace(s.Section) == "" {
		return fmt.Errorf("section is required")
	}
	if strings.TrimSpace(s.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if strings.TrimSpace(s.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if !validSeverities[s.Severity] {
		return fmt.Errorf("invalid severity %q", s.Severity)
	}
	if !validOperators[s.Expected.Operator] {
		return fmt.Errorf("invalid expected.operator %q", s.Expected.Operator)
	}

	switch s.APISource.Kind {
	case "graph":
		if s.APISource.Version != "v1.0" && s.APISource.Version != "beta" {
			return fmt.Errorf("api_source.version must be \"v1.0\" or \"beta\", got %q", s.APISource.Version)
		}
		if s.APISource.Method != "GET" {
			return fmt.Errorf("api_source.method must be \"GET\" (read-only), got %q", s.APISource.Method)
		}
		if !strings.HasPrefix(s.APISource.Endpoint, "/") {
			return fmt.Errorf("api_source.endpoint must start with '/', got %q", s.APISource.Endpoint)
		}
		if len(s.APISource.Permissions) == 0 {
			return fmt.Errorf("api_source.permissions must contain at least one read-only permission")
		}
		for _, p := range s.APISource.Permissions {
			if strings.Contains(p, "Write") || strings.Contains(p, "ReadWrite") {
				return fmt.Errorf("write permission %q is not permitted in read-only blueprint-drift", p)
			}
		}
		if s.Expected.Operator == "manual" {
			return fmt.Errorf("graph setting cannot use expected.operator \"manual\"")
		}
	case "manual":
		if strings.TrimSpace(s.APISource.ManualReason) == "" {
			return fmt.Errorf("api_source.manual_reason is required when kind is \"manual\"")
		}
		if s.Expected.Operator != "manual" {
			return fmt.Errorf("manual setting must use expected.operator \"manual\", got %q", s.Expected.Operator)
		}
	default:
		return fmt.Errorf("api_source.kind must be \"graph\" or \"manual\", got %q", s.APISource.Kind)
	}

	if len(s.ISMControls) == 0 {
		return fmt.Errorf("ism_controls must contain at least one ISM-XXXX entry")
	}
	for _, c := range s.ISMControls {
		if !reISMControl.MatchString(c) {
			return fmt.Errorf("invalid ISM control %q (expected ISM-XXXX)", c)
		}
	}
	for _, e8 := range s.EssentialEight {
		if !validEssentialEight[e8] {
			return fmt.Errorf("invalid essential_eight strategy %q", e8)
		}
	}
	if len(s.References) == 0 {
		return fmt.Errorf("references must contain at least one official https:// URL")
	}
	for _, ref := range s.References {
		if !strings.HasPrefix(ref, "https://") {
			return fmt.Errorf("reference %q must use https://", ref)
		}
	}
	return nil
}
