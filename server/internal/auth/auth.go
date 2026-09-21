package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxTimestampDrift is the maximum allowed time difference between
	// client and server timestamps.
	MaxTimestampDrift = 30 * time.Second

	// NonceCacheSize is the maximum number of nonces to store.
	NonceCacheSize = 10000

	// NonceTTL is how long a nonce is remembered for replay protection.
	NonceTTL = 60 * time.Second
)

// Authenticator validates HMAC-SHA256 auth tokens from WebSocket clients.
type Authenticator struct {
	secretKey  []byte
	nonceCache *nonceCache
}

// NewAuthenticator creates a new authenticator with the given secret key.
func NewAuthenticator(secretKey []byte) *Authenticator {
	return &Authenticator{
		secretKey:  secretKey,
		nonceCache: newNonceCache(NonceCacheSize, NonceTTL),
	}
}

// Validate checks the HMAC token, timestamp, and nonce.
// Returns nil on success, error describing the failure otherwise.
func (a *Authenticator) Validate(requestID, timestamp, nonce string) error {
	// Check timestamp
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	now := time.Now().Unix()
	drift := time.Duration(math.Abs(float64(now-ts))) * time.Second
	if drift > MaxTimestampDrift {
		return fmt.Errorf("timestamp drift too large: %v", drift)
	}

	// Check nonce not reused (replay protection)
	if a.nonceCache.has(nonce) {
		return fmt.Errorf("nonce already used (replay attack)")
	}

	// Compute expected HMAC
	message := timestamp + nonce
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	expectedB64 := base64.StdEncoding.EncodeToString(expectedMAC)

	// Constant-time comparison
	if !hmac.Equal([]byte(requestID), []byte(expectedB64)) {
		return fmt.Errorf("HMAC mismatch")
	}

	// Mark nonce as used
	a.nonceCache.add(nonce)

	return nil
}

// --- Nonce Cache with LRU eviction and TTL ---

type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

type nonceCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	order   []nonceEntry
	maxSize int
	ttl     time.Duration
}

func newNonceCache(maxSize int, ttl time.Duration) *nonceCache {
	nc := &nonceCache{
		entries: make(map[string]time.Time, maxSize),
		order:   make([]nonceEntry, 0, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
	// Start cleanup goroutine
	go nc.cleanup()
	return nc
}

func (nc *nonceCache) has(nonce string) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	expires, ok := nc.entries[nonce]
	if !ok {
		return false
	}
	// Check if expired
	if time.Now().After(expires) {
		delete(nc.entries, nonce)
		return false
	}
	return true
}

func (nc *nonceCache) add(nonce string) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	expiresAt := time.Now().Add(nc.ttl)
	nc.entries[nonce] = expiresAt
	nc.order = append(nc.order, nonceEntry{nonce: nonce, expiresAt: expiresAt})

	// Evict oldest if over capacity
	for len(nc.entries) > nc.maxSize && len(nc.order) > 0 {
		oldest := nc.order[0]
		nc.order = nc.order[1:]
		delete(nc.entries, oldest.nonce)
	}
}

func (nc *nonceCache) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nc.mu.Lock()
		now := time.Now()
		// Remove expired entries
		for nonce, expires := range nc.entries {
			if now.After(expires) {
				delete(nc.entries, nonce)
			}
		}
		// Compact order slice
		newOrder := make([]nonceEntry, 0, len(nc.order))
		for _, e := range nc.order {
			if _, ok := nc.entries[e.nonce]; ok {
				newOrder = append(newOrder, e)
			}
		}
		nc.order = newOrder
		nc.mu.Unlock()
	}
}
