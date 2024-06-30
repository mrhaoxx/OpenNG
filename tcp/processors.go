package tcp

import (
	"net"

	"github.com/mrhaoxx/OpenNG/log"

	"github.com/pires/go-proxyproto"
)

func NewTCPProxyProtocolHandler(allowedsrcs []string) ServiceHandler {
	mapallowed := make(map[string]bool)
	for _, v := range allowedsrcs {
		mapallowed[v] = true
	}
	return NewServiceFunction(func(conn *Conn) SerRet {
		sorce := conn.Addr().String()
		sourceip, _, err := net.SplitHostPort(sorce)
		if err != nil || !mapallowed[sourceip] {
			log.Println("sys", "[PROXYPROTOCOL]", "Disallowed Source IP Addr", sourceip)
			return Close
		}
		conn.Upgrade(proxyproto.NewConn(conn.TopConn()), "")
		return Continue
	})
}
