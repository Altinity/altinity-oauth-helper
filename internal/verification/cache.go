package verification

import (
	"sync"
	"time"
)

// cacheMaxEntries bounds in-memory growth. Each entry is ~256 B with typical
// claims/principal payloads; at 10000 entries the cache footprint is
// ~2.5 MiB. Preserved from the pre-refactor cmd/ch-jwt-verify cache — see
// CLAUDE.md's cache-correctness rule and the plan's "Cache mechanics"
// section.
const cacheMaxEntries = 10000

// cacheEntry is one cached verification outcome, keyed by cacheKey(). result
// is nil for a negative entry; err is nil for a positive entry.
type cacheEntry struct {
	ok        bool
	result    *Result
	err       error
	expiresAt time.Time
}

// cache is a bounded, mutex-protected map of cacheEntry. It knows nothing
// about verification semantics (TTL policy, exp capping, transient-error
// exemption) — that lives in Verifier; cache only owns storage mechanics:
// capacity, eviction, pruning, and returning "not found or expired" on a
// stale hit.
type cache struct {
	mu         sync.Mutex
	entries    map[string]cacheEntry
	maxEntries int // 0 = unlimited (used by tests)
}

func newCache(maxEntries int) *cache {
	return &cache{
		entries:    make(map[string]cacheEntry),
		maxEntries: maxEntries,
	}
}

// get returns the entry for key if present and not yet expired. An expired
// entry is treated identically to "not found" — the caller re-verifies from
// scratch; pruneExpired (and the next evicting set) will eventually reclaim
// its memory.
func (c *cache) get(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, found := c.entries[key]
	if !found || !time.Now().Before(entry.expiresAt) {
		return cacheEntry{}, false
	}
	return entry, true
}

// set inserts or overwrites the entry for key, first evicting if the cache
// is at capacity: expired entries are dropped first (cheap and correct); if
// still at capacity, the entry closest to expiry is dropped.
func (c *cache) set(key string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfNeededLocked()
	c.entries[key] = entry
}

func (c *cache) evictIfNeededLocked() {
	if c.maxEntries <= 0 || len(c.entries) < c.maxEntries {
		return
	}
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxEntries {
		return
	}
	var earliestKey string
	var earliestAt time.Time
	for k, e := range c.entries {
		if earliestKey == "" || e.expiresAt.Before(earliestAt) {
			earliestKey, earliestAt = k, e.expiresAt
		}
	}
	delete(c.entries, earliestKey)
}

// pruneExpired walks the cache once and drops entries whose TTL has
// elapsed. Called from the background reaper.
func (c *cache) pruneExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
