package tcp

import (
	"net/url"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
	. "github.com/mrhaoxx/OpenNG/pkg/ngtcp"
	"github.com/rs/zerolog/log"
)

func init() {
	registerDetector()
	registerController()
	registerListener()
	registerProxier()
	registerProxyProtocolHandler()

	var detectors map[string]Detector = map[string]Detector{
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
		ng.Register("det::"+name, ng.Assert{Type: "null"}, ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.TypeOf[Detector]()}}, func(*ng.ArgNode) (any, error) {
			return det, nil
		})

	}

}

func registerDetector() {
	ng.RegisterFunc("tcp::det", ngtcp.NewDetect)
}

func registerController() {
	ng.RegisterFunc("tcp::controller", ngtcp.NewTcpController)
}

type ListenConfig struct {
	AddressBindings []string          `ng:"AddressBindings"`
	Ptr             *ngtcp.Controller `ng:"ptr"`
}

func Listen(cfg ListenConfig) (any, error) {
	ctl := cfg.Ptr

	for _, addr := range cfg.AddressBindings {
		if err := ctl.Listen(addr); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func registerListener() {
	ng.RegisterFunc("tcp::listen", Listen)
}

func registerProxier() {
	ng.Register("tcp::proxier",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"hosts": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {Type: "string", Required: true},
								"backend": {
									Type:     "url",
									Required: true,
									Default:  &opennet.URL{URL: url.URL{Scheme: "tcp"}, Interface: "sys"},
								},
								"protocol": {Type: "string", Required: true},
							},
						},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			hosts := spec.MustGet("hosts").ToList()

			proxier := NewTcpProxier()

			for _, host := range hosts {
				name := host.MustGet("name").ToString()
				backend := host.MustGet("backend").ToURL()
				protocol := host.MustGet("protocol").ToString()

				if err := proxier.Add(name, backend.Host, protocol); err != nil {
					return nil, err
				}

				log.Debug().
					Str("name", name).
					Str("backend", backend.String()).
					Str("protocol", protocol).
					Msg("new tcp proxy host")
			}

			return proxier, nil
		},
	)
}

func registerProxyProtocolHandler() {
	ng.Register("tcp::proxyprotocolhandler",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"allowedsrcs": {
					Type:    "list",
					Default: []*ng.ArgNode{{Type: "string", Value: "127.0.0.1"}},
					Sub: ng.AssertMap{
						"_": {Type: "string"},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			allowedSrcs := spec.MustGet("allowedsrcs").ToStringList()
			log.Debug().Strs("allowedsrcs", allowedSrcs).Msg("new tcp proxy protocol handler")
			return NewTCPProxyProtocolHandler(allowedSrcs), nil
		},
	)
}
