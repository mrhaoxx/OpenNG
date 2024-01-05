package tcp

import (
	"net"

	"github.com/mrhaoxx/OpenNG/logging"

	"github.com/pires/go-proxyproto"
)

func NewTCPProxyProtocolHandler() ServiceHandler {
	return NewServiceFunction(func(conn *Conn) SerRet {
		sorce := conn.Addr().String()
		sourceip, _, err := net.SplitHostPort(sorce)
		if err != nil || sourceip != "127.0.0.1" {
			logging.Println("sys", "[PROXYPROTOCOL]", "Disallowed Source IP Addr", sourceip)
			return Close
		}
		conn.Upgrade(proxyproto.NewConn(conn.TopConn()), "")
		return Continue
	})
}
