package ratelimit

// Test-only access to a Limiter's bounds and bookkeeping. These are not part of
// the production API: nothing outside the tests sets the cap or reads the size
// (app#467 review-5x: a production tuning knob belongs in the ADR-0037 D1
// declaration, not in a setter).

// WithMaxBuckets sets the cap on the number of buckets (n < 1 is treated as 1:
// a limiter must be able to hold the bucket it is using).
func (l *Limiter) WithMaxBuckets(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	l.maxBuckets = n
	return l
}

// Len is the number of buckets currently held.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Examined is how many buckets the expiry sweep and the cap eviction have
// looked at in total.
func (l *Limiter) Examined() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.examined
}
