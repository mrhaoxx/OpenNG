package tls

import (
	"crypto/tls"

	tcp "github.com/mrhaoxx/OpenNG/tcp"
)

func (mgr *TlsMgr) Handle(c *tcp.Conn) tcp.SerRet {
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
	return tcp.Close
}
