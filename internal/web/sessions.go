package web

// sessions.go — the hub's session registry: one live analyzer dashboard per
// analyzer ID. `exalm serve` owns a SessionRegistry; analyzer `--open` runs
// attach their parsed corpus via POST /api/ingest/session (ingest.go), and
// the per-dashboard scoped routes resolve against it. Everything is
// in-memory; re-ingesting an analyzer replaces its previous session.

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// SessionHandlers bundles the per-session closures the web layer serves.
// Built by cmd/exalm (which owns the LLM client, redactor, and stores) via
// ServeOpts.BuildSessionHandlers.
type SessionHandlers struct {
	Converse        func(ctx context.Context, req ConverseRequest) (*plugin.Conversation, error)
	GetConversation func(ctx context.Context, id string) (*plugin.Conversation, error)
	AnalyzeLine     func(ctx context.Context, req LogAnalyzeRequest) (string, error)
	LogQuery        func(ctx context.Context, req LogQueryRequest) (LogQueryResponse, error)
}

// DashSession is one live analyzer dashboard hosted by the hub.
type DashSession struct {
	Analyzer    string
	Session     *investigate.LogSession
	Stats       any // analyzer-typed in-process, json.RawMessage when ingested
	Handlers    SessionHandlers
	CollectedAt time.Time
	IngestedAt  time.Time
}

// SessionRegistry is a concurrency-safe map of analyzer ID → live session.
type SessionRegistry struct {
	mu sync.RWMutex
	m  map[string]*DashSession
}

// NewSessionRegistry returns an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{m: make(map[string]*DashSession)}
}

// Put stores (or replaces) the analyzer's session.
func (r *SessionRegistry) Put(s *DashSession) {
	if s == nil || s.Analyzer == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s.Analyzer] = s
}

// Get returns the analyzer's live session, if any.
func (r *SessionRegistry) Get(id string) (*DashSession, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.m[id]
	return s, ok
}

// IDs returns the attached analyzer IDs, sorted.
func (r *SessionRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for id := range r.m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
