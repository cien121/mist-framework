package mistcore

import (
	"sync"
	"time"
)

// NonceCache records AUTH nonces to block replays (SPEC G9).
// Entries expire after ttl; cleanup runs lazily on insert.
type NonceCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[[12]byte]int64 // nonce -> expiry unix nano
}

// NewNonceCache creates a cache with the given entry TTL.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, m: make(map[[12]byte]int64)}
}

// Seen reports whether nonce was already recorded. If not, it records it
// and returns false. Safe for concurrent use.
func (c *NonceCache) Seen(nonce [12]byte) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.m[nonce]; ok && exp > now.UnixNano() {
		return true
	}
	// Lazy cleanup when the map grows.
	if len(c.m) > 65536 {
		for k, exp := range c.m {
			if exp <= now.UnixNano() {
				delete(c.m, k)
			}
		}
	}
	c.m[nonce] = now.Add(c.ttl).UnixNano()
	return false
}
