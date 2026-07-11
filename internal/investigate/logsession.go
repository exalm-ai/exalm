package investigate

// logsession.go — the in-memory analysis session for log-based analyzers
// (syslog, httplog, eventlog, iis, logs). One-shot CLI analyses parse their
// input into a bounded, queryable corpus of normalized events; serve mode
// hands the session to the investigation engine as the domain Facts, so
// collectors answer "what happened before?" / "show previous errors" from
// the corpus without re-reading files, and the dashboard's chart-to-log
// drilldown queries the same data.
//
// MEMORY-ONLY: the session is never persisted (the conversation transcript
// persists via convo.Store, already redacted). RemoteParams.Password is
// tagged json:"-" defensively even though the session is never serialized.

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Session bounds: past these caps the OLDEST events are dropped and the
// Truncated counter grows — surfaced in the dashboard footer so bounded
// coverage is never mistaken for full coverage.
const (
	MaxSessionEvents = 200_000
	MaxSessionBytes  = 64 << 20 // 64 MiB of Raw+Message text
)

// LogEvent is one normalized log entry, whatever the source format. The
// json tags define the hub-ingest wire shape (see snapshot.go).
type LogEvent struct {
	At       time.Time `json:"at,omitempty"`       // zero when the line had no parseable timestamp
	Severity string    `json:"severity,omitempty"` // normalized: emerg|alert|crit|err|warn|notice|info|debug, or 2xx..5xx class, or Information|Warning|Error|Critical
	Scope    string    `json:"scope,omitempty"`    // host / vhost / site
	Unit     string    `json:"unit,omitempty"`     // systemd unit / route / provider / app pool
	Code     string    `json:"code,omitempty"`     // event ID / HTTP status / exit code
	Message  string    `json:"message,omitempty"`
	Raw      string    `json:"raw,omitempty"` // original line (bounded by the parser)
	Source   int       `json:"source"`        // index into Sources
}

// SourceDesc identifies where events came from — a local file OR a remote
// host+channel.
type SourceDesc struct {
	Path    string `json:"path,omitempty"`
	Host    string `json:"host,omitempty"`
	Channel string `json:"channel,omitempty"` // log name / site / path on the remote
}

// RemoteParams carries what on-demand SSH diagnostics need. Password lives
// in memory only.
type RemoteParams struct {
	Host     string `json:"host"`
	User     string `json:"user,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
	Port     int    `json:"port,omitempty"`
	Password string `json:"-"`
	// OSFamily is "linux" or "windows" — set by the collecting plugin, it
	// selects which allowlist variant a diagnostic command uses.
	OSFamily string `json:"osFamily,omitempty"`
	// Plugin-specific collection params (log path/dir/channel).
	LogPath string `json:"logPath,omitempty"`
	LogDir  string `json:"logDir,omitempty"`
	LogName string `json:"logName,omitempty"`
}

// LogSession is one analysis run's parsed corpus + stats.
type LogSession struct {
	Analyzer    string
	Sources     []SourceDesc
	SSH         *RemoteParams // nil for local-only analyses
	DiagTier    string        // "off" | "readonly" | "full" — resolved config+flag
	Stats       any           // analyzer-typed; serialized into the dashboard payload
	CollectedAt time.Time

	mu        sync.RWMutex
	events    []LogEvent
	bytes     int
	truncated int
}

// NewLogSession builds an empty session for an analyzer.
func NewLogSession(analyzer string) *LogSession {
	return &LogSession{Analyzer: analyzer, CollectedAt: time.Now().UTC()}
}

// AddSource registers a source and returns its index for LogEvent.Source.
func (s *LogSession) AddSource(d SourceDesc) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Sources = append(s.Sources, d)
	return len(s.Sources) - 1
}

// Append adds events, enforcing the caps (drop-oldest).
func (s *LogSession) Append(events ...LogEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		s.events = append(s.events, e)
		s.bytes += len(e.Raw) + len(e.Message)
	}
	for (len(s.events) > MaxSessionEvents || s.bytes > MaxSessionBytes) && len(s.events) > 0 {
		s.bytes -= len(s.events[0].Raw) + len(s.events[0].Message)
		s.events = s.events[1:]
		s.truncated++
	}
}

// Len returns the number of retained events.
func (s *LogSession) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Truncated returns how many events were dropped to the caps.
func (s *LogSession) Truncated() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.truncated
}

// LogQuery filters the corpus. Zero values mean "no filter". Contains is a
// case-insensitive substring over Message+Raw. Limit 0 => 200.
type LogQuery struct {
	From, To time.Time
	Severity string
	Unit     string
	Scope    string
	Code     string
	Contains string
	Limit    int
	Offset   int
}

// Query returns matching events (in corpus order) and the TOTAL match count
// before Limit/Offset — so the UI can paginate honestly.
func (s *LogSession) Query(q LogQuery) ([]LogEvent, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	contains := strings.ToLower(q.Contains)
	var out []LogEvent
	total := 0
	for _, e := range s.events {
		if !matchesQuery(e, q, contains) {
			continue
		}
		total++
		if total <= q.Offset {
			continue
		}
		if len(out) < limit {
			out = append(out, e)
		}
	}
	return out, total
}

func matchesQuery(e LogEvent, q LogQuery, containsLower string) bool {
	if !q.From.IsZero() && !e.At.IsZero() && e.At.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !e.At.IsZero() && e.At.After(q.To) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
		return false
	}
	if q.Unit != "" && !strings.EqualFold(e.Unit, q.Unit) {
		return false
	}
	if q.Scope != "" && !strings.EqualFold(e.Scope, q.Scope) {
		return false
	}
	if q.Code != "" && e.Code != q.Code {
		return false
	}
	if containsLower != "" &&
		!strings.Contains(strings.ToLower(e.Message), containsLower) &&
		!strings.Contains(strings.ToLower(e.Raw), containsLower) {
		return false
	}
	return true
}

// Window returns up to limit events around a center time (before + after),
// in corpus order — the "what happened before/after?" primitive.
func (s *LogSession) Window(center time.Time, before, after time.Duration, limit int) []LogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	from, to := center.Add(-before), center.Add(after)
	var out []LogEvent
	for _, e := range s.events {
		if e.At.IsZero() || e.At.Before(from) || e.At.After(to) {
			continue
		}
		if len(out) < limit {
			out = append(out, e)
		}
	}
	return out
}

// Vocabulary returns the distinct units and scopes seen in the corpus,
// sorted — this is what generic focus resolution matches user messages
// against ("is nginx failing?" → unit nginx.service).
func (s *LogSession) Vocabulary() (units, scopes []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	us, ss := map[string]bool{}, map[string]bool{}
	for _, e := range s.events {
		if e.Unit != "" {
			us[e.Unit] = true
		}
		if e.Scope != "" {
			ss[e.Scope] = true
		}
	}
	for u := range us {
		units = append(units, u)
	}
	for sc := range ss {
		scopes = append(scopes, sc)
	}
	sort.Strings(units)
	sort.Strings(scopes)
	return units, scopes
}

// TimeRange returns the earliest and latest timestamped events' times
// (zero,zero when nothing is timestamped).
func (s *LogSession) TimeRange() (from, to time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.events {
		if e.At.IsZero() {
			continue
		}
		if from.IsZero() || e.At.Before(from) {
			from = e.At
		}
		if to.IsZero() || e.At.After(to) {
			to = e.At
		}
	}
	return from, to
}

// ResolveFocusFromVocabulary is the generic focus resolver for corpus-based
// analyzers: an explicit "scope/name" mention wins, then a unit named in the
// message, then a scope, else the prior focus persists (pronoun follow-ups).
func ResolveFocusFromVocabulary(prev, message string, s *LogSession) string {
	if s == nil {
		return prev
	}
	lower := strings.ToLower(message)
	units, scopes := s.Vocabulary()
	for _, u := range units {
		if u != "" && strings.Contains(lower, strings.ToLower(u)) {
			// Attach the unit's scope when unambiguous.
			for _, sc := range scopes {
				if sc != "" {
					return sc + "/" + u
				}
			}
			return u
		}
	}
	for _, sc := range scopes {
		if sc != "" && strings.Contains(lower, strings.ToLower(sc)) {
			return sc
		}
	}
	return prev
}
