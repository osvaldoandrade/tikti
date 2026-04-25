package saml

import (
	"sync"
	"time"
)

// Clock abstracts time so that consumers can be tested without real sleeps.
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
}

// SystemClock delegates to the standard time package.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// Since returns the elapsed duration since t.
func (SystemClock) Since(t time.Time) time.Duration { return time.Since(t) }

// FakeClock is a deterministic clock for tests.
// It starts at 2026-01-01T00:00:00Z and only moves forward via Advance.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock starting at 2026-01-01T00:00:00Z.
func NewFakeClock() *FakeClock {
	return &FakeClock{
		now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// Now returns the fake current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Since returns the duration elapsed on the fake clock since t.
func (c *FakeClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

// Advance moves the fake clock forward by d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
