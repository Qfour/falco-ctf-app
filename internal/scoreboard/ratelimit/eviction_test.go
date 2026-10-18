package ratelimit_test

// app#463: the Limiter's bucket map is bounded. Buckets that are idle past the
// TTL and refilled are dropped (judged on the REFILLED token count, not the
// stale stored one), the map never exceeds the cap, a full map evicts the least
// recently used bucket instead of refusing the new key, and none of it scans
// the map.

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Unix(1_000_000, 0)} }

func TestEviction_PartlyDrainedBucketIsDroppedOnceRefilledAndIdle(t *testing.T) {
	c := newClock()
	l := ratelimit.New(1 /* tok/s */, 10).WithNow(c.now)
	for i := 0; i < 3; i++ { // stored tokens = 7 < burst: the old condition never held
		l.Allow("a")
	}
	if l.Len() != 1 {
		t.Fatalf("Len = %d, want 1", l.Len())
	}
	c.advance(6 * time.Minute) // idle past the 5 min TTL; refilled to the burst long ago
	l.Allow("b")
	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d after the TTL, want 1: the long-idle, refilled bucket %q was kept (stale stored tokens judged instead of refilled)", got, "a")
	}
}

func TestEviction_NotDroppedWithinTTLOrBeforeRefill(t *testing.T) {
	t.Run("within the TTL", func(t *testing.T) {
		c := newClock()
		l := ratelimit.New(1, 10).WithNow(c.now)
		l.Allow("a")
		c.advance(4 * time.Minute)
		l.Allow("b")
		if l.Len() != 2 {
			t.Fatalf("Len = %d, want 2: a bucket was dropped before the TTL", l.Len())
		}
	})
	t.Run("idle past the TTL but not yet refilled keeps its debt", func(t *testing.T) {
		c := newClock()
		l := ratelimit.New(0.001 /* 1 token / 1000 s */, 10).WithNow(c.now)
		for i := 0; i < 10; i++ {
			l.Allow("a")
		}
		c.advance(6 * time.Minute) // 0.36 tokens: still < 1
		if l.Allow("a") {
			t.Fatal("a drained bucket must still deny after 6 minutes at 0.001 tok/s")
		}
		if l.Len() != 1 {
			t.Fatalf("Len = %d, want 1", l.Len())
		}
	})
}

func TestEviction_CapIsNeverExceededAndEvictsLeastRecentlyUsed(t *testing.T) {
	c := newClock()
	const max = 100
	l := ratelimit.New(0.1, 1).WithNow(c.now).WithMaxBuckets(max)
	l.Allow("hot")
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
		l.Allow("hot") // keeps "hot" the most recently used
		if got := l.Len(); got > max {
			t.Fatalf("Len = %d after %d keys, cap is %d", got, i+1, max)
		}
	}
	if l.Len() != max {
		t.Fatalf("Len = %d, want the cap %d once it is reached", l.Len(), max)
	}
	// "hot" survived: its single token is spent, so it still denies.
	if l.Allow("hot") {
		t.Fatal("the recently used bucket was evicted (it was handed a fresh token)")
	}
	// k0 is the oldest of the first 100 and long gone: it is a fresh bucket.
	if !l.Allow("k0") {
		t.Fatal("an evicted key must start with a fresh bucket (a new key is never refused)")
	}
}

func TestEviction_AtTheCapANewKeyIsAdmittedNotRefused(t *testing.T) {
	c := newClock()
	l := ratelimit.New(0.1, 1).WithNow(c.now).WithMaxBuckets(3)
	for i := 0; i < 50; i++ {
		if !l.Allow(fmt.Sprintf("new%d", i)) {
			t.Fatalf("new key #%d was refused at the cap: refusing new keys would lock honest keys out (app#359)", i)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}
}

func TestEviction_BelowTheCapBehaviourIsUnchanged(t *testing.T) {
	c := newClock()
	l := ratelimit.New(1, 2).WithNow(c.now).WithMaxBuckets(10)
	for _, k := range []string{"a", "b", "c"} {
		if !l.Allow(k) || !l.Allow(k) || l.Allow(k) {
			t.Fatalf("%s: want exactly burst=2 allowed then denied", k)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3: nothing may be evicted below the cap", l.Len())
	}
	c.advance(3 * time.Second)
	if !l.Allow("a") {
		t.Fatal("a refilled bucket must allow again")
	}
}

// 100k distinct keys through a small cap: with the old per-call scan of the map
// this is on the order of 5e8 iterations; the test passes in milliseconds only
// if Allow no longer scans.
func TestEviction_ManyKeysThroughASmallCapDoNotScan(t *testing.T) {
	c := newClock()
	l := ratelimit.New(0.1, 1).WithNow(c.now).WithMaxBuckets(5000)
	start := time.Now()
	for i := 0; i < 100000; i++ {
		l.Allow(fmt.Sprintf("ip-%d", i))
	}
	if l.Len() != 5000 {
		t.Fatalf("Len = %d, want 5000", l.Len())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("100k Allow calls took %s: the map is being scanned per call", d)
	}
}

func TestEviction_ConcurrentCallersStayWithinTheCap(t *testing.T) {
	l := ratelimit.New(0.1, 1).WithMaxBuckets(200)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				l.Allow(fmt.Sprintf("g%d-%d", g, i))
			}
		}(g)
	}
	wg.Wait()
	if got := l.Len(); got > 200 {
		t.Fatalf("Len = %d after concurrent use, cap is 200", got)
	}
}

func TestEviction_MaxBucketsBelowOneIsOne(t *testing.T) {
	l := ratelimit.New(1, 1).WithMaxBuckets(0)
	l.Allow("a")
	l.Allow("b")
	if l.Len() != 1 {
		t.Fatalf("Len = %d, want 1", l.Len())
	}
}
