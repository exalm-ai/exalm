// Package changestore persists a chronological log of cluster changes:
// Deployments updated, ConfigMaps edited, RoleBindings created, etc. The store
// is the foundation for Phase 4's change-correlation engine, which ties recent
// changes to currently-failing pods.
//
// Competitive gap:
//   - Komodor's "change timeline" is their signature UI element (strengths #1
//     and #4 in komodor_config.json) — Exalm needs an equivalent.
//   - OpenObserve's RCF anomaly model has zero change-point awareness
//     (openobserve_config.json weakness #6: "post-deployment metric shifts always
//     score as anomalies regardless of whether a Helm release caused them").
//
// Storage model: append-only JSON-lines file at $EXALM_HOME/changes.jsonl, or
// ~/.exalm/changes.jsonl by default. Reads stream the file. Bounded rotation
// at 10 MB keeps the file size predictable; older entries are truncated.
//
// The store is process-safe via a single mutex on the *Store value, NOT
// inter-process safe — only one writer process is expected (the daemon or
// CLI run). Multiple readers across processes work fine.
package changestore

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxFileBytes triggers rotation. Keep small enough that scanning is cheap.
const MaxFileBytes int64 = 10 * 1024 * 1024 // 10 MB

// ChangeEvent describes a single cluster mutation observed by the change tracker.
type ChangeEvent struct {
	// ID is a deterministic hash of (Kind+Namespace+Name+NewRev+Timestamp).
	// Stable so the UI can correlate the same event across refreshes.
	ID string `json:"id"`
	// Kind is the Kubernetes object kind: "Deployment", "ConfigMap",
	// "RoleBinding", "Secret", "StatefulSet", "CronJob", ...
	Kind string `json:"kind"`
	// Namespace is empty for cluster-scoped resources.
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// Action is "created", "updated", or "deleted".
	Action string `json:"action"`
	// Actor is the user or controller that made the change. From the K8s
	// audit log when available; falls back to "controller" or "unknown".
	Actor string `json:"actor,omitempty"`
	// OldRev / NewRev are resourceVersion strings before/after the change.
	OldRev string `json:"old_rev,omitempty"`
	NewRev string `json:"new_rev,omitempty"`
	// DiffURL optionally links to a PR/commit explaining the change.
	DiffURL string `json:"diff_url,omitempty"`
	// Timestamp is when the change was observed.
	Timestamp time.Time `json:"timestamp"`
}

// MakeID returns the deterministic ID for a ChangeEvent, computed over the
// stable fields. Call this before Append to populate event.ID.
func MakeID(e ChangeEvent) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", e.Kind, e.Namespace, e.Name, e.NewRev, e.Timestamp.UTC().Format(time.RFC3339Nano)) //nolint:errcheck // hash.Write never fails
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:16]
}

// Store is the on-disk change ledger.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open returns a Store backed by the file at path. The file (and its parent
// directory) is created if it doesn't exist. The caller can pass an empty
// path to use the default location.
func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create dir %q: %w", dir, err)
	}
	// Touch the file so subsequent reads don't fail.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is internal data file from config, not arbitrary user input
	if err != nil {
		return nil, fmt.Errorf("open changestore %q: %w", path, err)
	}
	_ = f.Close()
	return &Store{path: path}, nil
}

// DefaultPath returns $EXALM_HOME/changes.jsonl, or ~/.exalm/changes.jsonl.
func DefaultPath() string {
	if h := os.Getenv("EXALM_HOME"); h != "" {
		return filepath.Join(h, "changes.jsonl")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "changes.jsonl"
	}
	return filepath.Join(home, ".exalm", "changes.jsonl")
}

// Path returns the on-disk path the store is using. Useful for tests.
func (s *Store) Path() string { return s.path }

// Append writes an event to the ledger. If event.ID is empty, MakeID is used.
// If the file exceeds MaxFileBytes after the write, rotation is triggered:
// the oldest half of entries is dropped.
func (s *Store) Append(e ChangeEvent) error {
	if e.Kind == "" || e.Name == "" {
		return errors.New("changestore: Kind and Name are required")
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = MakeID(e)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: s.path is an internal data file from config
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Best-effort rotation. Failures here are not fatal — the next call retries.
	if fi, err := f.Stat(); err == nil && fi.Size() > MaxFileBytes {
		_ = s.rotateLocked()
	}
	return nil
}

// rotateLocked drops the oldest 50% of entries. Caller must hold s.mu.
func (s *Store) rotateLocked() error {
	all, err := readAll(s.path)
	if err != nil {
		return err
	}
	if len(all) < 2 {
		return nil
	}
	keep := all[len(all)/2:]
	tmp := s.path + ".rot"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: tmp is derived from internal store path, not arbitrary user input
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range keep {
		line, _ := json.Marshal(e)
		_, _ = w.Write(append(line, '\n'))
	}
	_ = w.Flush()
	_ = f.Close()
	return os.Rename(tmp, s.path)
}

// All returns every event since `since`. Pass time.Time{} to return all events.
// Results are sorted oldest-first.
func (s *Store) All(since time.Time) ([]ChangeEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := readAll(s.path)
	if err != nil {
		return nil, err
	}
	if since.IsZero() {
		return all, nil
	}
	out := make([]ChangeEvent, 0, len(all))
	for _, e := range all {
		if !e.Timestamp.Before(since) {
			out = append(out, e)
		}
	}
	return out, nil
}

// RecentForResource returns events affecting (Namespace, Name) whose Kind
// matches one of the supplied kinds, within `window` before `now`. Pass an
// empty kinds slice to match any Kind. Pod failures often correlate with
// changes to the owning Deployment or ConfigMap, so callers commonly pass
// {"Deployment", "ConfigMap", "Secret", "RoleBinding"} along with the pod's
// owner workload name.
func (s *Store) RecentForResource(ns, name string, kinds []string, window time.Duration, now time.Time) ([]ChangeEvent, error) {
	cutoff := now.Add(-window)
	all, err := s.All(cutoff)
	if err != nil {
		return nil, err
	}
	kindSet := map[string]bool{}
	for _, k := range kinds {
		kindSet[k] = true
	}
	var out []ChangeEvent
	for _, e := range all {
		if e.Namespace != ns {
			continue
		}
		if !strings.EqualFold(e.Name, name) && !strings.HasPrefix(name, e.Name+"-") {
			// Allow pod-name → owner-workload match: a Deployment "api-gateway"
			// owns pods like "api-gateway-7c9b-...".
			continue
		}
		if len(kindSet) > 0 && !kindSet[e.Kind] {
			continue
		}
		if e.Timestamp.After(now) {
			continue
		}
		out = append(out, e)
	}
	// Newest first — the most-recent change is the most likely cause.
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	return out, nil
}

// readAll parses every JSON line in the file. Malformed lines are skipped
// silently so a corrupted entry can't poison the entire store.
func readAll(path string) ([]ChangeEvent, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an internal data file, not user-controlled
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []ChangeEvent
	dec := json.NewDecoder(bufio.NewReader(f))
	for {
		var e ChangeEvent
		err := dec.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed entry; continue with rest.
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out, nil
}
