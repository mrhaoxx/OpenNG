package ngtls

import (
	"crypto/tls"
	"net"

	"github.com/mrhaoxx/OpenNG/modules/ngtcp"
)

func (mgr *TlsMgr) HandleTCP(c *ngtcp.Conn) ngtcp.Ret {
	hellov, ok := c.Load(ngtcp.KeyTLS)
	hello := hellov.(*tls.ClientHelloInfo)

	serverName := hello.ServerName
	if serverName == "" {
		// No SNI (e.g. connecting by IP) — use the local IP address
		host, _, _ := net.SplitHostPort(c.TopConn().LocalAddr().String())
		serverName = host
	}

	cert := mgr.getCertificate(serverName)
	if cert != nil {
		if !ok || len(hello.SupportedProtos) == 0 {
			ts := tls.Server(c.TopConn(), mgr.TlsConfig(cert, nil))
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
					c.Upgrade(tls.Server(c.TopConn(), mgr.TlsConfig(cert, []string{sp})), "HTTP1")
					return ngtcp.Upgrade
				case "h2":
					decodedTls := tls.Server(c.TopConn(), mgr.TlsConfig(cert, []string{sp}))
					decodedTls.Handshake()
					c.Upgrade(decodedTls, "HTTP2")
					return ngtcp.Upgrade
				default:
					c.Store(ngtcp.KeyTLS, sp)
					continue
				}
			}

			c.Upgrade(tls.Server(c.TopConn(), mgr.TlsConfig(cert, nil)), "")

			return ngtcp.Continue
		}
	}
	return ngtcp.Close
}

var _ ngtcp.Service = (*TlsMgr)(nil)
