package k8s

// evidcache.go is the per-conversation evidence cache: repeated questions in
// the same investigation reuse recently collected evidence instead of calling
// the cluster again. MEMORY-ONLY — cached evidence is never written to disk
// (the persisted transcript already carries redacted excerpts; the cache
// itself lives and dies with the process). A "refresh" request bypasses it.

import (
	"sync"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

const (
	// evidCacheMaxConvos / evidCacheMaxEntries bound memory: least-recently
	// used conversations and oldest entries are evicted past these caps.
	evidCacheMaxConvos  = 32
	evidCacheMaxEntries = 64
	// evidCacheIdleTTL drops a conversation's whole cache after inactivity.
	evidCacheIdleTTL = 30 * time.Minute
)

// collectorTTL is how long each collector class's evidence stays fresh.
// Fast-moving signals expire quickly; topology/config are more stable.
var collectorTTL = map[string]time.Duration{
	"previous-logs":     90 * time.Second,
	"metrics":           90 * time.Second,
	"service-endpoints": 90 * time.Second,
	"dns-heuristic":     90 * time.Second,
	"related-services":  90 * time.Second,
	"owner-chain":       5 * time.Minute,
	"node-detail":       5 * time.Minute,
	"configmaps":        5 * time.Minute,
	"secrets":           5 * time.Minute,
	"storage-chain":     5 * time.Minute,
	"scaling":           5 * time.Minute,
	"netpol":            5 * time.Minute,
	"rbac":              5 * time.Minute,
	"namespace-detail":  5 * time.Minute,
	"change-history":    10 * time.Minute,
	"history":           10 * time.Minute,
}

// ttlFor returns the collector's freshness window (default 5 minutes).
func ttlFor(collector string) time.Duration {
	if ttl, ok := collectorTTL[collector]; ok {
		return ttl
	}
	return 5 * time.Minute
}

// cachedEvidence is one collector run's output.
type cachedEvidence struct {
	Steps    []plugin.InvestigationStep
	Evidence []plugin.EvidenceItem
	At       time.Time
}

// convoCache holds one conversation's entries, keyed collector+"\x1f"+target.
type convoCache struct {
	entries  map[string]cachedEvidence
	order    []string // insertion order for oldest-first eviction
	lastUsed time.Time
}

// evidenceCache is the process-wide cache, keyed by conversation ID.
type evidenceCache struct {
	mu     sync.Mutex
	convos map[string]*convoCache
}

func newEvidenceCache() *evidenceCache {
	return &evidenceCache{convos: map[string]*convoCache{}}
}

func cacheKey(collector, target string) string { return collector + "\x1f" + target }

// get returns the cached run and whether it is still fresh.
func (c *evidenceCache) get(convoID, collector, target string, now time.Time) (cachedEvidence, bool) {
	if c == nil || convoID == "" {
		return cachedEvidence{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cc := c.convos[convoID]
	if cc == nil {
		return cachedEvidence{}, false
	}
	cc.lastUsed = now
	entry, ok := cc.entries[cacheKey(collector, target)]
	if !ok || now.Sub(entry.At) > ttlFor(collector) {
		return cachedEvidence{}, false
	}
	return entry, true
}

// put stores a collector run, evicting the oldest entry / least-recently-used
// conversation past the caps.
func (c *evidenceCache) put(convoID, collector, target string, entry cachedEvidence, now time.Time) {
	if c == nil || convoID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cc := c.convos[convoID]
	if cc == nil {
		if len(c.convos) >= evidCacheMaxConvos {
			c.evictLRULocked()
		}
		cc = &convoCache{entries: map[string]cachedEvidence{}}
		c.convos[convoID] = cc
	}
	cc.lastUsed = now
	key := cacheKey(collector, target)
	if _, exists := cc.entries[key]; !exists {
		if len(cc.order) >= evidCacheMaxEntries {
			oldest := cc.order[0]
			cc.order = cc.order[1:]
			delete(cc.entries, oldest)
		}
		cc.order = append(cc.order, key)
	}
	cc.entries[key] = entry
}

// evictLRULocked removes the least-recently-used conversation. Caller holds mu.
func (c *evidenceCache) evictLRULocked() {
	var lruID string
	var lruAt time.Time
	for id, cc := range c.convos {
		if lruID == "" || cc.lastUsed.Before(lruAt) {
			lruID, lruAt = id, cc.lastUsed
		}
	}
	if lruID != "" {
		delete(c.convos, lruID)
	}
}

// purge drops conversations idle longer than evidCacheIdleTTL. Called
// opportunistically at the start of each turn — no background goroutine.
func (c *evidenceCache) purge(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, cc := range c.convos {
		if now.Sub(cc.lastUsed) > evidCacheIdleTTL {
			delete(c.convos, id)
		}
	}
}

// has reports whether a fresh entry exists (used by the planner to mark
// steps "cached" before execution).
func (c *evidenceCache) has(convoID, collector, target string, now time.Time) bool {
	_, ok := c.get(convoID, collector, target, now)
	return ok
}
