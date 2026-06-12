package ngnet

import (
	"net"
	"testing"
	"time"
)

func dialAndRead(t *testing.T, addr string) (string, bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func echoHandler(tag string) func(net.Conn) {
	return func(c net.Conn) {
		c.Write([]byte(tag))
		c.Close()
	}
}

func TestListenerRegistryHandoffAndFallback(t *testing.T) {
	reg := newListenerRegistry()
	const addr = "127.0.0.1:18990"

	release1, err := reg.Acquire("tcp", addr, echoHandler("gen1"))
	if err != nil {
		t.Fatalf("acquire gen1: %v", err)
	}
	if got, ok := dialAndRead(t, addr); !ok || got != "gen1" {
		t.Fatalf("expected gen1 to serve, got %q (%v)", got, ok)
	}

	// A second acquisition takes over without closing the port.
	release2, err := reg.Acquire("tcp", addr, echoHandler("gen2"))
	if err != nil {
		t.Fatalf("acquire gen2: %v", err)
	}
	if got, ok := dialAndRead(t, addr); !ok || got != "gen2" {
		t.Fatalf("expected gen2 to take over, got %q (%v)", got, ok)
	}

	// Releasing the newest holder falls back to the previous one —
	// the failed-reload semantics: the port never goes dark.
	release2()
	if got, ok := dialAndRead(t, addr); !ok || got != "gen1" {
		t.Fatalf("expected fallback to gen1, got %q (%v)", got, ok)
	}

	// Releasing out of order must be safe; releasing the last holder
	// actually closes the listener.
	release2() // idempotent
	release1()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after last release")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The address must be reusable after full release.
	release3, err := reg.Acquire("tcp", addr, echoHandler("gen3"))
	if err != nil {
		t.Fatalf("re-acquire after close: %v", err)
	}
	defer release3()
	if got, ok := dialAndRead(t, addr); !ok || got != "gen3" {
		t.Fatalf("expected gen3 after re-acquire, got %q (%v)", got, ok)
	}
}

func TestListenerRegistryMidStackRelease(t *testing.T) {
	reg := newListenerRegistry()
	const addr = "127.0.0.1:18991"

	release1, err := reg.Acquire("tcp", addr, echoHandler("gen1"))
	if err != nil {
		t.Fatalf("acquire gen1: %v", err)
	}
	release2, err := reg.Acquire("tcp", addr, echoHandler("gen2"))
	if err != nil {
		t.Fatalf("acquire gen2: %v", err)
	}

	// Old generation retires while the new one is active: no change for
	// traffic, and the port survives.
	release1()
	if got, ok := dialAndRead(t, addr); !ok || got != "gen2" {
		t.Fatalf("expected gen2 to keep serving, got %q (%v)", got, ok)
	}
	release2()
}
