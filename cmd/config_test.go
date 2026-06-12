package ngcmd

import (
	"net"
	"testing"
	"time"

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
    Records:
      - Name: test.local
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

func TestReloadRetiresOldGeneration(t *testing.T) {
	if err := LoadCfg([]byte(lifecycleCfg), false); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	gen1 := CurSpace
	waitListening(t, "127.0.0.1:18987")

	if err := LoadCfg([]byte(lifecycleCfg), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if CurSpace == gen1 {
		t.Fatal("CurSpace not swapped on reload")
	}

	// The port must still be served by the new generation after the old
	// one was stopped (identity-guarded cleanup must not kill the
	// successor's listener).
	waitListening(t, "127.0.0.1:18987")

	// Retire the final generation: the port must actually go dark.
	CurSpace.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for dialOK(t, "tcp", "127.0.0.1:18987") {
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after Stop")
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

	CurSpace.Stop()
	CurSpace = nil
}
