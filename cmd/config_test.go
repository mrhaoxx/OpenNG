package ngcmd

import (
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	_ "github.com/mrhaoxx/OpenNG/modules/dns"
	_ "github.com/mrhaoxx/OpenNG/modules/ngtcp"
)

const lifecycleCfg = `
version: 7
Config:
  Logger:
    TimeZone: Local
    Verbose: false
    Outputs: []
Services:
  tcp:
    kind: tcp::controller
    listen:
      - 127.0.0.1:18987
  dns:
    kind: dns::server
    AddressBindings:
      - 127.0.0.1:15353
    Filters:
      - Name: "*"
        Allowance: true
    Records:
      - Name: "test.local."
        Type: A
        Value: 127.0.0.1
`

func dialOK(t *testing.T, network, addr string) bool {
	t.Helper()
	conn, err := net.DialTimeout(network, addr, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if dialOK(t, "tcp", addr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never came up", addr)
}

func queryDNS(t *testing.T, addr string) bool {
	t.Helper()
	m := new(mdns.Msg)
	m.SetQuestion("test.local.", mdns.TypeA)
	c := mdns.Client{Timeout: time.Second}
	r, _, err := c.Exchange(m, addr)
	return err == nil && r != nil && len(r.Answer) > 0
}

func waitDNS(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if queryDNS(t, addr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dns %s never answered", addr)
}

func TestReloadRetiresOldGeneration(t *testing.T) {
	if err := LoadCfg([]byte(lifecycleCfg), false); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	gen1 := CurSpace
	waitListening(t, "127.0.0.1:18987")
	waitDNS(t, "127.0.0.1:15353")

	if err := LoadCfg([]byte(lifecycleCfg), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if CurSpace == gen1 {
		t.Fatal("CurSpace not swapped on reload")
	}

	// The TCP port must still be served by the new generation after the
	// old one was stopped, and DNS must keep answering across the
	// SO_REUSEPORT handoff.
	waitListening(t, "127.0.0.1:18987")
	waitDNS(t, "127.0.0.1:15353")

	// Retire the final generation: both ports must actually go dark.
	CurSpace.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for dialOK(t, "tcp", "127.0.0.1:18987") {
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after Stop")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for queryDNS(t, "127.0.0.1:15353") {
		if time.Now().After(deadline) {
			t.Fatal("dns still answering after Stop")
		}
		time.Sleep(20 * time.Millisecond)
	}
	CurSpace = nil
}

func TestFailedReloadRetiresHalfBuiltGeneration(t *testing.T) {
	if err := LoadCfg([]byte(lifecycleCfg), false); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	gen1 := CurSpace
	waitListening(t, "127.0.0.1:18987")

	// Reload with a config whose second service fails: the tcp controller
	// of the half-built generation must be stopped, not leaked.
	bad := lifecycleCfg + `
  broken:
    kind: does::not::exist
`
	if err := LoadCfg([]byte(bad), true); err == nil {
		t.Fatal("expected reload failure")
	}
	if CurSpace != gen1 {
		t.Fatal("CurSpace must stay on the old generation after failed reload")
	}

	// The half-built generation released its addresses on retirement: TCP
	// falls back via the listener registry, UDP via SO_REUSEPORT — both
	// must still be served by the old generation.
	waitListening(t, "127.0.0.1:18987")
	waitDNS(t, "127.0.0.1:15353")

	CurSpace.Stop()
	CurSpace = nil
}
