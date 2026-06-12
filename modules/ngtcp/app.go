package ngtcp

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func init() {
	ng.RegisterFunc("tcp::det", NewDetect)
	ng.RegisterFunc("tcp::controller", NewTcpController)
	ng.RegisterFunc("tcp::proxier", NewTcpProxier)
	ng.RegisterFunc("tcp::proxyprotocolhandler", NewTCPProxyProtocolHandler)

	var detectors map[string]Detector = map[string]Detector{
		"tls":           DetectTLS,
		"http":          DetectHTTP,
		"socks5":        DetectSOCKS5,
		"ssh":           DetectSSH,
		"minecraft":     DetectMinecraft,
		"rdp":           DetectRDP,
		"trojan":        DetectTROJAN,
		"proxyprotocol": DetectPROXYPROTOCOL,
	}

	for name, det := range detectors {
		ng.RegisterFunc("det::"+name, func(struct{}) (Detector, error) {
			return det, nil
		})
	}

}

type ListenConfig struct {
	AddressBindings []string    `ng:"AddressBindings"`
	Ptr             *Controller `ng:"ptr"`
}

var _ ng.Stopper = (*Controller)(nil)
