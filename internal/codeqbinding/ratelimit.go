package codeqbinding

import (
	"sync"
	"time"
)

const defaultMaximumTrackedIdentities = 16384

// IdentityRateLimiter is an in-process sliding-window limit of exchange
// attempts per Pod identity (clusterRef, namespace, ServiceAccount, podUid).
// It is per replica: N Tikti replicas allow at most N x limit per window.
// Memory is bounded; when the bound is reached and no expired identity can be
// evicted, new identities are refused (fail closed).
type IdentityRateLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	maxEntries int
	now        func() time.Time
	attempts   map[string][]time.Time
}

func NewIdentityRateLimiter(limit int, window time.Duration) *IdentityRateLimiter {
	return &IdentityRateLimiter{
		limit: limit, window: window, maxEntries: defaultMaximumTrackedIdentities,
		now: time.Now, attempts: make(map[string][]time.Time),
	}
}

// IdentityKey joins the verified identity dimensions without ambiguity.
func IdentityKey(clusterRef, namespace, serviceAccount, podUID string) string {
	return clusterRef + "\x00" + namespace + "\x00" + serviceAccount + "\x00" + podUID
}

// Allow records one attempt for key. When refused it returns the whole number
// of seconds (>= 1) after which the oldest attempt leaves the window.
func (l *IdentityRateLimiter) Allow(key string) (bool, int) {
	if l == nil || l.limit < 1 || l.window <= 0 {
		return false, 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	recent := pruneAttempts(l.attempts[key], now.Add(-l.window))
	if len(recent) == 0 {
		delete(l.attempts, key)
		if len(l.attempts) >= l.maxEntries {
			l.evictExpired(now)
			if len(l.attempts) >= l.maxEntries {
				return false, retrySeconds(l.window)
			}
		}
	}
	if len(recent) >= l.limit {
		l.attempts[key] = recent
		return false, retrySeconds(recent[0].Add(l.window).Sub(now))
	}
	l.attempts[key] = append(recent, now)
	return true, 0
}

func (l *IdentityRateLimiter) evictExpired(now time.Time) {
	cutoff := now.Add(-l.window)
	for key, attempts := range l.attempts {
		if recent := pruneAttempts(attempts, cutoff); len(recent) == 0 {
			delete(l.attempts, key)
		} else {
			l.attempts[key] = recent
		}
	}
}

func pruneAttempts(attempts []time.Time, cutoff time.Time) []time.Time {
	index := 0
	for index < len(attempts) && !attempts[index].After(cutoff) {
		index++
	}
	if index == 0 {
		return attempts
	}
	return append([]time.Time(nil), attempts[index:]...)
}

func retrySeconds(wait time.Duration) int {
	seconds := int((wait + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
