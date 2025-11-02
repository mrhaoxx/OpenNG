package tcp

import (
	"net"
	"sync"

	ngnet "github.com/mrhaoxx/OpenNG/pkg/net"
)

type tcphost struct {
	ID      string `json:"id"`
	Backend string `json:"backend"`
}

type tcpproxy struct {
	hosts map[string]tcphost
	mu    sync.Mutex
}

func (tpx *tcpproxy) Handle(c *Conn) SerRet {
	a, ok := tpx.hosts[(c.Protocols())]
	if ok {
		oc, err := net.Dial("tcp", a.Backend)
		if err == nil {
			ngnet.ConnSync((c.TopConn()), oc)
		}
	}
	return Close
}

func (tpx *tcpproxy) Get() map[string]tcphost {
	tpx.mu.Lock()
	defer tpx.mu.Unlock()
	ret := map[string]tcphost{}
	for k, v := range tpx.hosts {
		ret[k] = v
	}
	return ret
}

func (tpx *tcpproxy) Add(id string, host string, protocol string) error {
	tpx.mu.Lock()
	defer tpx.mu.Unlock()
	tpx.hosts[protocol] = tcphost{
		ID:      id,
		Backend: host,
	}
	return nil
}

func (tpx *tcpproxy) Reset() {
	tpx.mu.Lock()
	defer tpx.mu.Unlock()
	tpx.hosts = map[string]tcphost{}
}

func NewTcpProxier() *tcpproxy {
	tpx := &tcpproxy{
		hosts: make(map[string]tcphost),
	}
	return tpx
}
