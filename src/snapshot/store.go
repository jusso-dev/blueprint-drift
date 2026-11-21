package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jusso-dev/blueprint-drift/src/engine"
)

// SchemaVersion identifies the local JSON snapshot document format.
const SchemaVersion = "1.0"

// Snapshot stores the full evaluated state of a tenant at a point in time.
type Snapshot struct {
	SchemaVersion    string                     `json:"schema_version"`
	RunID            string                     `json:"run_id"`
	TenantID         string                     `json:"tenant_id"`
	BlueprintVersion string                     `json:"blueprint_version"`
	CapturedAt       time.Time                  `json:"captured_at"`
	Summary          engine.Summary             `json:"summary"`
	SnapshotSHA256   string                     `json:"snapshot_sha256"`
	Settings         map[string]SettingSnapshot `json:"settings"`
}

// SettingSnapshot records the evaluated state of a single Blueprint setting.
type SettingSnapshot struct {
	SettingID      string          `json:"setting_id"`
	Section        string          `json:"section"`
	Title          string          `json:"title"`
	Status         engine.Status   `json:"status"`
	Severity       engine.Severity `json:"severity"`
	Expected       any             `json:"expected,omitempty"`
	Actual         any             `json:"actual,omitempty"`
	Message        string          `json:"message"`
	Query          string          `json:"query"`
	ResponseSHA256 string          `json:"response_sha256,omitempty"`
	ISMControls    []string        `json:"ism_controls,omitempty"`
}

// IndexEntry is a lightweight manifest row stored in snapshots/index.json.
type IndexEntry struct {
	RunID            string         `json:"run_id"`
	File             string         `json:"file"`
	TenantID         string         `json:"tenant_id"`
	BlueprintVersion string         `json:"blueprint_version"`
	CapturedAt       time.Time      `json:"captured_at"`
	Summary          engine.Summary `json:"summary"`
	SnapshotSHA256   string         `json:"snapshot_sha256"`
}

// Index lists all snapshots saved in a Store directory.
type Index struct {
	SchemaVersion string       `json:"schema_version"`
	Snapshots     []IndexEntry `json:"snapshots"`
}

// FromRun converts a drift engine.RunResult into a canonical Snapshot with a
// deterministic SHA-256 digest over its settings map.
func FromRun(run *engine.RunResult) (*Snapshot, error) {
	if run == nil {
		return nil, fmt.Errorf("run result is nil")
	}
	settings := make(map[string]SettingSnapshot, len(run.Results))
	for _, r := range run.Results {
		settings[r.SettingID] = SettingSnapshot{
			SettingID:      r.SettingID,
			Section:        r.Section,
			Title:          r.Title,
			Status:         r.Status,
			Severity:       r.Severity,
			Expected:       r.Expected,
			Actual:         r.Actual,
			Message:        r.Message,
			Query:          r.Query,
			ResponseSHA256: r.ResponseSHA256,
			ISMControls:    append([]string(nil), r.ISMControls...),
		}
	}

	canonicalBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical settings: %w", err)
	}
	sum := sha256.Sum256(canonicalBytes)

	return &Snapshot{
		SchemaVersion:    SchemaVersion,
		RunID:            run.RunID,
		TenantID:         run.TenantID,
		BlueprintVersion: run.BlueprintVersion,
		CapturedAt:       run.GeneratedAt.UTC(),
		Summary:          run.Summary,
		SnapshotSHA256:   hex.EncodeToString(sum[:]),
		Settings:         settings,
	}, nil
}

// Store persists Snapshot JSON files and an index manifest inside a local directory.
type Store struct {
	Dir string
}

// NewStore returns a local JSON snapshot Store rooted at dir.
func NewStore(dir string) *Store {
	return &Store{Dir: dir}
}

// Save writes snap atomically to <Dir>/<run_id>.json and updates index.json.
func (s *Store) Save(snap *Snapshot) (string, error) {
	if snap == nil {
		return "", fmt.Errorf("snapshot is nil")
	}
	if strings.TrimSpace(snap.RunID) == "" {
		return "", fmt.Errorf("snapshot run_id is required")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return "", fmt.Errorf("create snapshot store %s: %w", s.Dir, err)
	}

	fileName := sanitizeRunID(snap.RunID) + ".json"
	fullPath := filepath.Join(s.Dir, fileName)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal snapshot: %w", err)
	}
	data = append(data, '\n')

	if err := atomicWrite(fullPath, data); err != nil {
		return "", fmt.Errorf("write snapshot %s: %w", fullPath, err)
	}

	idx, err := s.loadIndex()
	if err != nil {
		return "", err
	}
	entry := IndexEntry{
		RunID:            snap.RunID,
		File:             fileName,
		TenantID:         snap.TenantID,
		BlueprintVersion: snap.BlueprintVersion,
		CapturedAt:       snap.CapturedAt.UTC(),
		Summary:          snap.Summary,
		SnapshotSHA256:   snap.SnapshotSHA256,
	}

	replaced := false
	for i := range idx.Snapshots {
		if idx.Snapshots[i].RunID == snap.RunID {
			idx.Snapshots[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		idx.Snapshots = append(idx.Snapshots, entry)
	}
	sort.Slice(idx.Snapshots, func(i, j int) bool {
		if idx.Snapshots[i].CapturedAt.Equal(idx.Snapshots[j].CapturedAt) {
			return idx.Snapshots[i].RunID < idx.Snapshots[j].RunID
		}
		return idx.Snapshots[i].CapturedAt.Before(idx.Snapshots[j].CapturedAt)
	})

	idxBytes, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal snapshot index: %w", err)
	}
	idxBytes = append(idxBytes, '\n')
	if err := atomicWrite(filepath.Join(s.Dir, "index.json"), idxBytes); err != nil {
		return "", fmt.Errorf("write snapshot index: %w", err)
	}
	return fullPath, nil
}

// LoadFile reads a Snapshot directly from a JSON file path.
func LoadFile(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	if snap.SchemaVersion == "" || snap.RunID == "" {
		return nil, fmt.Errorf("invalid snapshot file %s: missing schema_version or run_id", path)
	}
	return &snap, nil
}

// Load resolves ref either as an explicit file path or as a run ID inside s.Dir.
func (s *Store) Load(ref string) (*Snapshot, error) {
	if _, err := os.Stat(ref); err == nil {
		return LoadFile(ref)
	}
	candidate := filepath.Join(s.Dir, sanitizeRunID(ref)+".json")
	if _, err := os.Stat(candidate); err == nil {
		return LoadFile(candidate)
	}
	return nil, fmt.Errorf("snapshot %q not found as file or in store %s", ref, s.Dir)
}

// List returns chronologically ordered snapshot index entries.
func (s *Store) List() ([]IndexEntry, error) {
	idx, err := s.loadIndex()
	if err != nil {
		return nil, err
	}
	return idx.Snapshots, nil
}

// Latest loads the most recent snapshot from the store.
func (s *Store) Latest() (*Snapshot, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no snapshots found in %s", s.Dir)
	}
	last := entries[len(entries)-1]
	return LoadFile(filepath.Join(s.Dir, last.File))
}

func (s *Store) loadIndex() (*Index, error) {
	idxPath := filepath.Join(s.Dir, "index.json")
	raw, err := os.ReadFile(idxPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Index{SchemaVersion: SchemaVersion}, nil
		}
		return nil, fmt.Errorf("read snapshot index: %w", err)
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("parse snapshot index: %w", err)
	}
	if idx.SchemaVersion == "" {
		idx.SchemaVersion = SchemaVersion
	}
	return &idx, nil
}

func sanitizeRunID(id string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_", " ", "_")
	return replacer.Replace(strings.TrimSpace(id))
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-snapshot-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
