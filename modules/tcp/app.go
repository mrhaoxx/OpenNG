package tcp

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
)

func init() {
	ng.RegisterFunc("tcp::det", ngtcp.NewDetect)
	ng.RegisterFunc("tcp::controller", ngtcp.NewTcpController)
	ng.RegisterFunc("tcp::proxier", ngtcp.NewTcpProxier)
	ng.RegisterFunc("tcp::proxyprotocolhandler", ngtcp.NewTCPProxyProtocolHandler)

	var detectors map[string]ngtcp.Detector = map[string]ngtcp.Detector{
		"tls":           ngtcp.DetectTLS,
		"http":          ngtcp.DetectHTTP,
		"socks5":        ngtcp.DetectSOCKS5,
		"ssh":           ngtcp.DetectSSH,
		"minecraft":     ngtcp.DetectMinecraft,
		"rdp":           ngtcp.DetectRDP,
		"trojan":        ngtcp.DetectTROJAN,
		"proxyprotocol": ngtcp.DetectPROXYPROTOCOL,
	}

	for name, det := range detectors {
		ng.RegisterFunc("det::"+name, func(struct{}) (ngtcp.Detector, error) {
			return det, nil
		})
	}

}

type ListenConfig struct {
	AddressBindings []string          `ng:"AddressBindings"`
	Ptr             *ngtcp.Controller `ng:"ptr"`
}
