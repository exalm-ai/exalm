package investigate

// evidcache.go — the per-conversation evidence cache, moved verbatim from
// plugins/k8s. MEMORY-ONLY: cached evidence is never written to disk (the
// persisted transcript already carries redacted excerpts). TTLs come from
// the Profile; a "refresh" request bypasses the cache.

import (
	"sync"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

const (
	evidCacheMaxConvos  = 32
	evidCacheMaxEntries = 64
	evidCacheIdleTTL    = 30 * time.Minute
	defaultTTL          = 5 * time.Minute
)

// cachedEvidence is one collector run's output.
type cachedEvidence struct {
	Steps    []plugin.InvestigationStep
	Evidence []plugin.EvidenceItem
	At       time.Time
}

// convoCache holds one conversation's entries, keyed collector+"\x1f"+target.
type convoCache struct {
	entries  map[string]cachedEvidence
	order    []string
	lastUsed time.Time
}

// evidenceCache is the engine-owned cache, keyed by conversation ID.
type evidenceCache struct {
	mu     sync.Mutex
	ttls   map[string]time.Duration // injected from the Profile
	convos map[string]*convoCache
}

func newEvidenceCache(ttls map[string]time.Duration) *evidenceCache {
	return &evidenceCache{ttls: ttls, convos: map[string]*convoCache{}}
}

func (c *evidenceCache) ttlFor(collector string) time.Duration {
	if c != nil {
		if ttl, ok := c.ttls[collector]; ok {
			return ttl
		}
	}
	return defaultTTL
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
	if !ok || now.Sub(entry.At) > c.ttlFor(collector) {
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
