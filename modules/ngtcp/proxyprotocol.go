package ngtcp

import (
	"net"

	"github.com/pires/go-proxyproto"
	zlog "github.com/rs/zerolog/log"
)

func NewTCPProxyProtocolHandler(allowedsrcs []string) (Service, error) {
	mapallowed := make(map[string]bool)
	for _, v := range allowedsrcs {
		mapallowed[v] = true
	}
	return NewServiceFunction(func(conn *Conn) Ret {
		sorce := conn.Addr().String()
		sourceip, _, err := net.SplitHostPort(sorce)
		if err != nil || !mapallowed[sourceip] {
			zlog.Warn().Str("type", "tcp/proxyprotocol").Str("sourceip", sourceip).Msg("disallowed source ip addr")
			return Close
		}
		conn.Upgrade(proxyproto.NewConn(conn.TopConn()), "")
		return Continue
	}), nil
}
