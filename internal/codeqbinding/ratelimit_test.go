package codeqbinding

import (
	"sync"
	"testing"
	"time"
)

func TestIdentityRateLimiterSlidingWindow(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	limiter := NewIdentityRateLimiter(6, time.Minute)
	limiter.now = func() time.Time { return now }
	key := IdentityKey("conveste-hostgator", "workload-conveste", "cflow", "pod-a")
	for attempt := 0; attempt < 6; attempt++ {
		if allowed, _ := limiter.Allow(key); !allowed {
			t.Fatalf("attempt %d refused", attempt)
		}
		now = now.Add(5 * time.Second)
	}
	allowed, retry := limiter.Allow(key)
	if allowed || retry != 30 {
		t.Fatalf("seventh = %v retry=%d, want refused after 30 s", allowed, retry)
	}
	if allowed, _ := limiter.Allow(IdentityKey("conveste-hostgator", "workload-conveste", "cflow", "pod-b")); !allowed {
		t.Fatal("another Pod shares the budget")
	}
	if allowed, _ := limiter.Allow(IdentityKey("code-cloud", "workload-conveste", "cflow", "pod-a")); !allowed {
		t.Fatal("another cluster shares the budget")
	}
	now = now.Add(31 * time.Second)
	if allowed, _ := limiter.Allow(key); !allowed {
		t.Fatal("oldest attempt did not leave the window")
	}
}

func TestIdentityRateLimiterBoundedMemoryFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	limiter := NewIdentityRateLimiter(1, time.Minute)
	limiter.maxEntries = 2
	limiter.now = func() time.Time { return now }
	for _, pod := range []string{"a", "b"} {
		if allowed, _ := limiter.Allow(pod); !allowed {
			t.Fatalf("pod %s refused", pod)
		}
	}
	if allowed, retry := limiter.Allow("c"); allowed || retry < 1 {
		t.Fatalf("new identity admitted past the bound: %v %d", allowed, retry)
	}
	now = now.Add(61 * time.Second)
	if allowed, _ := limiter.Allow("c"); !allowed {
		t.Fatal("expired identities were not evicted")
	}
	var nilLimiter *IdentityRateLimiter
	if allowed, _ := nilLimiter.Allow("x"); allowed {
		t.Fatal("nil limiter admitted")
	}
}

func TestIdentityRateLimiterConcurrentUse(t *testing.T) {
	limiter := NewIdentityRateLimiter(6, time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for index := 0; index < 50; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if allowed, _ := limiter.Allow("same-pod"); allowed {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 6 {
		t.Fatalf("admitted %d concurrent attempts, want 6", admitted)
	}
}
