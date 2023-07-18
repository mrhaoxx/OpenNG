package tls

import (
	"crypto/tls"

	tcp "github.com/haoxingxing/OpenNG/tcp"
	utils "github.com/haoxingxing/OpenNG/utils"
)

type tlsMgr struct {
	certs  map[string]certificate
	lookup *utils.BufferedLookup
}

func NewTlsMgr() *tlsMgr {

	var mgr = tlsMgr{
		certs: make(map[string]certificate),
	}

	mgr.lookup = utils.NewBufferedLookup(func(s string) interface{} {
		for k, v := range mgr.certs {
			if v.dnsnames.MatchString(s) {
				return k
			}
		}
		return "unmatched"
	})

	return &mgr
}

func (mgr *tlsMgr) Handle(c *tcp.Connection) tcp.SerRet {
	hellov, ok := c.Load(tcp.KeyTLS)
	hello := hellov.(*tls.ClientHelloInfo)

	cert := mgr.getCertificate(hello.ServerName)
	if cert != nil {
		if !ok || len(hello.SupportedProtos) == 0 {
			ts := tls.Server(c.TopConn(), &tls.Config{
				Certificates: []tls.Certificate{*cert},
			})
			ts.Handshake()
			c.Upgrade(ts, "")
			return tcp.Continue
		} else {
			for _, sp := range hello.SupportedProtos {
				switch sp {
				case "http/1.1":
					c.Upgrade(tls.Server(c.TopConn(), &tls.Config{
						Certificates: []tls.Certificate{*cert},
						NextProtos:   []string{sp},
					}), "HTTP1")
					return tcp.Upgrade
				case "h2":
					decodedTls := tls.Server(
						c.TopConn(), &tls.Config{
							Certificates: []tls.Certificate{*cert},
							NextProtos:   []string{sp},
						})
					decodedTls.Handshake()
					c.Upgrade(decodedTls, "HTTP2")
					return tcp.Upgrade
				default:
					c.Store(tcp.KeyTLS, sp)
					continue
				}
			}
		}
	}
	return tcp.Continue
}
