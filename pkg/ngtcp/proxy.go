package ngtcp

import (
	"sync"

	ngnet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

type ProxyHost struct {
	ID       string    `ng:"name"`
	Protocol string    `ng:"protocol"`
	Backend  ngnet.URL `ng:"backend"`
}

type Proxier struct {
	hosts map[string]ProxyHost
	mu    sync.Mutex
}

func (tpx *Proxier) HandleTCP(c *Conn) Ret {
	a, ok := tpx.hosts[(c.Protocols())]
	if ok {
		oc, err := a.Backend.Underlying.Dial("tcp", a.Backend.String())
		if err == nil {
			ngnet.ConnSync((c.TopConn()), oc)
		}
	}
	return Close
}

func (tpx *Proxier) Get() map[string]ProxyHost {
	tpx.mu.Lock()
	defer tpx.mu.Unlock()
	ret := map[string]ProxyHost{}
	for k, v := range tpx.hosts {
		ret[k] = v
	}
	return ret
}

type TcpProxierConfig struct {
	Hosts []ProxyHost `ng:"hosts"`
}

func NewTcpProxier(cfg TcpProxierConfig) (*Proxier, error) {
	tpx := &Proxier{
		hosts: make(map[string]ProxyHost),
	}
	for _, host := range cfg.Hosts {
		tpx.hosts[host.Protocol] = host
	}
	return tpx, nil
}

var _ Service = (*Proxier)(nil)
