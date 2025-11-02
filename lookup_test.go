package netgate

import (
	"strconv"
	"testing"
	"time"
)

func TestBufferedLookup_Lookup(t *testing.T) {
	BufferedLookup := NewBufferedLookup(func(s string) string {
		return "test"
	})
	if BufferedLookup.Lookup("test") != "test" {
		t.Error("BufferedLookup.Lookup() failed")
	}
}
func BenchmarkBufferedLookupNewKey(b *testing.B) {
	BufferedLookup := NewBufferedLookup(func(s string) string {
		return "test"
	})
	for n := 0; n < b.N; n++ {
		BufferedLookup.Lookup(strconv.Itoa(n))
	}
}
func BenchmarkBufferedLookupOldKey(b *testing.B) {
	BufferedLookup := NewBufferedLookup(func(s string) string {
		return "test"
	})
	for n := 0; n < b.N; n++ {
		BufferedLookup.Lookup("test")
	}
}
func BenchmarkBufferedLookupOldKeyDelayed1ms(b *testing.B) {
	BufferedLookup := NewBufferedLookup(func(s string) string {
		time.Sleep(1 * time.Millisecond)
		return "test"
	})
	for n := 0; n < b.N; n++ {
		BufferedLookup.Lookup("test")
	}
}
func BenchmarkBufferedLookupNewKeyelayed1ms(b *testing.B) {
	BufferedLookup := NewBufferedLookup(func(s string) string {
		time.Sleep(1 * time.Millisecond)
		return "test"
	})
	for n := 0; n < b.N; n++ {
		BufferedLookup.Lookup(strconv.Itoa(n))
	}
}
