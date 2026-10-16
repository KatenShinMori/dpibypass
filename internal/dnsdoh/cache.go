package dnsdoh

import (
	"net"
	"strings"
	"sync"
	"time"
)

// CacheEntryType distinguishes the kind of cached resolution outcome.
type CacheEntryType int

const (
	EntryPositive CacheEntryType = iota
	EntryNegative                // RFC 2308: NXDOMAIN or NODATA with valid SOA
	EntryFailure                 // RFC 9520: SERVFAIL, FormErr, Refused
)

type cacheKey struct {
	Name  string
	QType uint16
}

type cacheEntry struct {
	EntryType CacheEntryType
	IPs       []net.IP
	Err       error
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Cache provides a thread-safe, bounded, multi-category DNS cache.
type Cache struct {
	mu          sync.RWMutex
	entries     map[cacheKey]*cacheEntry
	maxCapacity int
}

// NewCache constructs a Cache with the given maximum capacity.
func NewCache(maxCapacity int) *Cache {
	if maxCapacity <= 0 {
		maxCapacity = 1024
	}
	return &Cache{
		entries:     make(map[cacheKey]*cacheEntry, maxCapacity),
		maxCapacity: maxCapacity,
	}
}

// Get looks up a cached entry for the given normalized domain and QType.
// Returns IPs, error, and a boolean indicating if a valid unexpired entry was found.
func (c *Cache) Get(domain string, qtype uint16, now time.Time) ([]net.IP, error, bool) {
	ips, _, err, found := c.GetWithTTL(domain, qtype, now)
	return ips, err, found
}

// GetWithTTL looks up a cached entry for the given normalized domain and QType.
// Returns IPs, remaining TTL, error, and a boolean indicating if a valid unexpired entry was found.
func (c *Cache) GetWithTTL(domain string, qtype uint16, now time.Time) ([]net.IP, time.Duration, error, bool) {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	key := cacheKey{Name: norm, QType: qtype}

	c.mu.RLock()
	entry, found := c.entries[key]
	c.mu.RUnlock()

	if !found {
		return nil, 0, nil, false
	}

	if now.After(entry.ExpiresAt) {
		// Expired entry
		c.mu.Lock()
		// Double check under write lock
		if e, ok := c.entries[key]; ok && now.After(e.ExpiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil, 0, nil, false
	}

	remTTL := entry.ExpiresAt.Sub(now)
	if remTTL < time.Second {
		remTTL = time.Second
	}

	switch entry.EntryType {
	case EntryPositive:
		// Return copy of IPs to prevent external mutations
		ipsCopy := make([]net.IP, len(entry.IPs))
		copy(ipsCopy, entry.IPs)
		return ipsCopy, remTTL, nil, true
	case EntryNegative, EntryFailure:
		return nil, remTTL, entry.Err, true
	default:
		return nil, 0, nil, false
	}
}

// PutPositive caches positive address records.
// Invariant: If ttl <= 0, the record is NOT cached (TTL zero means no caching).
func (c *Cache) PutPositive(domain string, qtype uint16, ips []net.IP, ttl time.Duration, now time.Time) {
	if ttl <= 0 || len(ips) == 0 {
		return
	}
	// Upper cap at 86400s (24h)
	if ttl > 86400*time.Second {
		ttl = 86400 * time.Second
	}

	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	key := cacheKey{Name: norm, QType: qtype}

	ipsCopy := make([]net.IP, len(ips))
	copy(ipsCopy, ips)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ensureCapacity(now)
	c.entries[key] = &cacheEntry{
		EntryType: EntryPositive,
		IPs:       ipsCopy,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
}

// PutNegative caches an authoritative negative result (NXDOMAIN or NODATA) per RFC 2308.
// Invariant: Must have a valid SOA-derived negative TTL > 0. If ttl <= 0, it is NOT cached.
func (c *Cache) PutNegative(domain string, qtype uint16, err error, negativeTTL time.Duration, now time.Time) {
	if negativeTTL <= 0 || err == nil {
		return
	}
	// RFC 2308 §5 recommendation: cap at 3600s (1h)
	if negativeTTL > 3600*time.Second {
		negativeTTL = 3600 * time.Second
	}

	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	key := cacheKey{Name: norm, QType: qtype}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ensureCapacity(now)
	c.entries[key] = &cacheEntry{
		EntryType: EntryNegative,
		Err:       err,
		ExpiresAt: now.Add(negativeTTL),
		CreatedAt: now,
	}
}

// PutFailure caches a transient DNS resolution failure (SERVFAIL, FormErr, Refused) per RFC 9520.
// Invariant: Clamped strictly to at least 1 second and no more than 5 minutes (RFC 9520).
func (c *Cache) PutFailure(domain string, qtype uint16, err error, duration time.Duration, now time.Time) {
	if err == nil {
		return
	}
	// RFC 9520 clamping: minimum 1 second, maximum 300 seconds (5 minutes)
	if duration < 1*time.Second {
		duration = 1 * time.Second
	} else if duration > 300*time.Second {
		duration = 300 * time.Second
	}

	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	key := cacheKey{Name: norm, QType: qtype}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ensureCapacity(now)
	c.entries[key] = &cacheEntry{
		EntryType: EntryFailure,
		Err:       err,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
	}
}

// ensureCapacity purges expired entries if approaching capacity, or evicts the oldest entry.
// Must be called with c.mu write lock held.
func (c *Cache) ensureCapacity(now time.Time) {
	if len(c.entries) < c.maxCapacity {
		return
	}

	// 1. Evict expired entries first
	for k, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, k)
		}
	}

	if len(c.entries) < c.maxCapacity {
		return
	}

	// 2. Still at capacity: evict oldest entry by CreatedAt
	var oldestKey cacheKey
	var oldestTime time.Time
	first := true

	for k, entry := range c.entries {
		if first || entry.CreatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.CreatedAt
			first = false
		}
	}

	if !first {
		delete(c.entries, oldestKey)
	}
}

// Len returns current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
