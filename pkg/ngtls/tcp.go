package ngtls

import (
	"crypto/tls"

	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
)

func (mgr *TlsMgr) HandleTCP(c *ngtcp.Conn) ngtcp.Ret {
	hellov, ok := c.Load(ngtcp.KeyTLS)
	hello := hellov.(*tls.ClientHelloInfo)

	cert := mgr.getCertificate(hello.ServerName)
	if cert != nil {
		if !ok || len(hello.SupportedProtos) == 0 {
			ts := tls.Server(c.TopConn(), &tls.Config{
				Certificates: []tls.Certificate{*cert},
			})
			err := ts.Handshake()
			if err != nil {
				return ngtcp.Close
			}
			c.Upgrade(ts, "")
			return ngtcp.Continue
		} else {
			for _, sp := range hello.SupportedProtos {
				switch sp {
				case "http/1.1":
					c.Upgrade(tls.Server(c.TopConn(), &tls.Config{
						Certificates: []tls.Certificate{*cert},
						NextProtos:   []string{sp},
					}), "HTTP1")
					return ngtcp.Upgrade
				case "h2":
					decodedTls := tls.Server(
						c.TopConn(), &tls.Config{
							Certificates: []tls.Certificate{*cert},
							NextProtos:   []string{sp},
						})
					decodedTls.Handshake()
					c.Upgrade(decodedTls, "HTTP2")
					return ngtcp.Upgrade
				default:
					c.Store(ngtcp.KeyTLS, sp)
					continue
				}
			}

			c.Upgrade(tls.Server(c.TopConn(), &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}), "")

			return ngtcp.Continue
		}
	}
	return ngtcp.Close
}

var _ ngtcp.Service = (*TlsMgr)(nil)
