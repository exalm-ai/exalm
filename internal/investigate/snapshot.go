package investigate

// snapshot.go — the hub-ingest wire form of a LogSession. The live session
// keeps its corpus in unexported, mutex-guarded fields, so plain
// json.Marshal would silently drop every event; SessionSnapshot is the
// explicit, complete serialization used by `--open` runs to hand their
// parsed corpus to a running `exalm serve` hub.
//
// SECURITY: RemoteParams.Password is tagged json:"-", so credentials never
// cross the wire — an ingested session therefore runs WITHOUT remote SSH
// diagnostics (corpus-only investigation). That trade is deliberate.

import (
	"encoding/json"
	"fmt"
	"time"
)

// SessionSnapshot is the JSON wire form of one analysis session.
type SessionSnapshot struct {
	Analyzer    string          `json:"analyzer"`
	Sources     []SourceDesc    `json:"sources,omitempty"`
	SSH         *RemoteParams   `json:"ssh,omitempty"` // Password excluded via json:"-"
	DiagTier    string          `json:"diagTier,omitempty"`
	Stats       json.RawMessage `json:"stats,omitempty"` // analyzer-typed, passed through untouched
	CollectedAt time.Time       `json:"collectedAt"`
	Events      []LogEvent      `json:"events"`
	Truncated   int             `json:"truncated,omitempty"`
}

// Snapshot captures the session's full state for ingest. Stats is marshaled
// once here so the hub can embed it in dashboard payloads without knowing
// the analyzer-specific type.
func (s *LogSession) Snapshot() (SessionSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := SessionSnapshot{
		Analyzer:    s.Analyzer,
		Sources:     append([]SourceDesc(nil), s.Sources...),
		SSH:         s.SSH,
		DiagTier:    s.DiagTier,
		CollectedAt: s.CollectedAt,
		Events:      append([]LogEvent(nil), s.events...),
		Truncated:   s.truncated,
	}
	if s.Stats != nil {
		blob, err := json.Marshal(s.Stats)
		if err != nil {
			return SessionSnapshot{}, fmt.Errorf("marshal session stats: %w", err)
		}
		snap.Stats = blob
	}
	return snap, nil
}

// RestoreLogSession rebuilds a live session from a snapshot. Events pass
// through Append so the memory caps hold even against an oversized or
// hostile snapshot. The restored session carries no SSH password (it never
// crossed the wire), so diagnostic collectors will report unavailable.
func RestoreLogSession(snap SessionSnapshot) (*LogSession, error) {
	if snap.Analyzer == "" {
		return nil, fmt.Errorf("snapshot has no analyzer name")
	}
	s := NewLogSession(snap.Analyzer)
	s.Sources = append([]SourceDesc(nil), snap.Sources...)
	s.SSH = snap.SSH
	s.DiagTier = snap.DiagTier
	if !snap.CollectedAt.IsZero() {
		s.CollectedAt = snap.CollectedAt
	}
	if len(snap.Stats) > 0 {
		s.Stats = snap.Stats // json.RawMessage: embedded verbatim in payloads
	}
	s.Append(snap.Events...)
	s.addTruncated(snap.Truncated)
	return s, nil
}

// addTruncated folds the snapshot's pre-ingest truncation count into the
// restored session so bounded coverage stays visible.
func (s *LogSession) addTruncated(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncated += n
}
