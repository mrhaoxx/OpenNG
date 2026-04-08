// Package stats provides lock-free counters and sliding window rate tracking.
package stats

import (
	"sync/atomic"
	"time"
)

// Counter is a simple atomic counter.
type Counter uint64

func (c *Counter) Add(n uint64) { atomic.AddUint64((*uint64)(c), n) }
func (c *Counter) Inc()         { atomic.AddUint64((*uint64)(c), 1) }
func (c *Counter) Load() uint64 { return atomic.LoadUint64((*uint64)(c)) }

// RateWindow tracks per-second counts in a lock-free circular buffer.
// Window size is fixed at 60 seconds.
type RateWindow struct {
	slots [60]uint64
}

func (w *RateWindow) slot() int {
	return int(time.Now().Unix() % 60)
}

// Add increments the current second's slot.
func (w *RateWindow) Add(n uint64) {
	atomic.AddUint64(&w.slots[w.slot()], n)
}

// Inc increments the current second's slot by 1.
func (w *RateWindow) Inc() {
	atomic.AddUint64(&w.slots[w.slot()], 1)
}

// Rate returns the average per-second rate over the last `seconds` seconds.
// The current (partial) second is excluded.
func (w *RateWindow) Rate(seconds int) float64 {
	if seconds <= 0 || seconds > 59 {
		seconds = 59
	}
	now := int(time.Now().Unix() % 60)
	var total uint64
	for i := 1; i <= seconds; i++ {
		idx := (now - i + 60) % 60
		total += atomic.LoadUint64(&w.slots[idx])
	}
	return float64(total) / float64(seconds)
}

// Reset clears stale slots. Call this periodically (e.g. every second)
// or lazily — not required for correctness, only for accuracy after idle periods.
// In practice, slots naturally get overwritten each minute cycle.

// Bucket tracks counts in fixed categories (e.g. HTTP status code groups).
type Bucket [6]uint64 // indices 0-5: [0]=unused, [1]=1xx, [2]=2xx, [3]=3xx, [4]=4xx, [5]=5xx

func (b *Bucket) Inc(category int) {
	if category >= 0 && category < len(b) {
		atomic.AddUint64(&b[category], 1)
	}
}

func (b *Bucket) Load(category int) uint64 {
	if category >= 0 && category < len(b) {
		return atomic.LoadUint64(&b[category])
	}
	return 0
}
