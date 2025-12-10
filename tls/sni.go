package tls

import (
	"crypto/tls"

	tcp "github.com/mrhaoxx/OpenNG/tcp"
	utils "github.com/mrhaoxx/OpenNG/utils"
)

type SniMatcher struct {
	Snis    utils.GroupRegexp
	Rewrite string
}

func (m *SniMatcher) Handle(c *tcp.Conn) tcp.SerRet {
	hellov, ok := c.Load(tcp.KeyTLS)

	if !ok {
		return tcp.Continue
	}
	hello := hellov.(*tls.ClientHelloInfo)
	if m.Snis == nil || m.Snis.MatchString(hello.ServerName) {
		c.IdentifiyProtocol(m.Rewrite)
		return tcp.Upgrade
	}

	return tcp.Continue
}
