package tcp

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	opennet "github.com/mrhaoxx/OpenNG/pkg/net"
	"github.com/rs/zerolog/log"
)

func init() {
	registerDetector()
	registerController()
	registerListener()
	registerProxier()
	registerProxyProtocolHandler()
}

func registerDetector() {
	ngmodules.Register("tcp::det",
		func(spec *ngmodules.ArgNode) (any, error) {
			protocols := spec.MustGet("protocols").ToStringList()
			timeout := spec.MustGet("timeout").ToDuration()
			timeoutProtocol := spec.MustGet("timeoutprotocol").ToString()

			var dets []Detector
			for _, p := range protocols {
				switch p {
				case "tls":
					dets = append(dets, DetectTLS)
				case "proxyprotocol":
					dets = append(dets, DetectPROXYPROTOCOL)
				case "ssh":
					dets = append(dets, DetectSSH)
				case "rdp":
					dets = append(dets, DetectRDP)
				case "http":
					dets = append(dets, DetectHTTP)
				case "socks5":
					dets = append(dets, DetectSOCKS5)
				case "minecraft":
					dets = append(dets, DetectMinecraft)
				case "trojan":
					dets = append(dets, DetectTROJAN)
				default:
					return nil, errors.New("unknown protocol: " + p)
				}
			}

			log.Debug().
				Strs("protocols", protocols).
				Dur("timeout", timeout).
				Str("timeoutprotocol", timeoutProtocol).
				Msg("new tcp detector")

			return &Detect{Dets: dets, Timeout: timeout, TimeoutProtocol: timeoutProtocol}, nil
		}, ngmodules.Assert{
			Type:     "map",
			Required: true,
			Sub: ngmodules.AssertMap{
				"protocols": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "string",
							Enum: []any{"tls", "http", "ssh", "rdp", "socks5", "proxyprotocol", "minecraft", "trojan"},
						},
					},
				},
				"timeout": {
					Type:    "duration",
					Default: time.Duration(0),
					Desc:    "timeout for detection, 0 means no timeout",
				},
				"timeoutprotocol": {
					Type:    "string",
					Default: "UNKNOWN",
					Desc:    "protocol to assume when timeout",
				},
			},
		},
	)
}

func registerController() {
	ngmodules.Register("tcp::controller",
		func(spec *ngmodules.ArgNode) (any, error) {
			services := spec.MustGet("services").ToMap()

			controller := NewTcpController()

			for name, srvs := range services {
				var bindings []ServiceBinding
				for i, srv := range srvs.ToList() {
					serviceName := srv.MustGet("name").ToString()
					logi := srv.MustGet("logi")
					service, ok := logi.Value.(ServiceHandler)
					if !ok {
						return nil, errors.New("ptr " + serviceName + " is not a tcp.ServiceHandler " + fmt.Sprintf("%T %#v", logi.Value, logi.Value))
					}

					bindings = append(bindings, ServiceBinding{
						Name:           serviceName,
						ServiceHandler: service,
					})

					log.Debug().
						Str("protocol", name).
						Int("index", i).
						Str("name", serviceName).
						Type("logi", logi.Value).
						Msg("bind tcp service")
				}

				controller.Bind(name, bindings...)
			}

			return controller, nil
		}, ngmodules.Assert{
			Type:     "map",
			Required: true,
			Desc:     "TCP connection controller that manages protocol detection and service routing",
			Sub: ngmodules.AssertMap{
				"services": {
					Type: "map",
					Desc: "protocol-specific service handlers, where key is the protocol name (e.g. '' (first inbound), 'TLS', 'HTTP1', 'TLS HTTP2', etc)",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "list",
							Desc: "ordered list of service handlers for each protocol",
							Sub: ngmodules.AssertMap{
								"_": {
									Type: "map",
									Sub: ngmodules.AssertMap{
										"name": {
											Type:     "string",
											Required: true,
											Desc:     "name of the service handler (used in connection logs)",
										},
										"logi": {
											Type:     "ptr",
											Required: true,
											Desc:     "pointer to service handler implementation (must implement tcp.ServiceHandler)",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	)
}

func registerListener() {
	ngmodules.Register("tcp::listen",
		func(spec *ngmodules.ArgNode) (any, error) {
			ctl, ok := spec.MustGet("ptr").Value.(interface{ Listen(addr string) error })
			if !ok {
				return nil, errors.New("ptr is not a tcp.Listener")
			}

			for _, addr := range spec.MustGet("AddressBindings").ToStringList() {
				if err := ctl.Listen(addr); err != nil {
					return nil, err
				}
				log.Debug().Str("addr", addr).Msg("tcp listen")
			}
			return nil, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"AddressBindings": {
					Type: "list",
					Desc: "tcp listen address",
					Sub: ngmodules.AssertMap{
						"_": {Type: "string", Enum: []any{"0.0.0.0:443", "0.0.0.0:80", "0.0.0.0:22"}, AllowNonEnum: true},
					},
				},
				"ptr": {
					Type:     "ptr",
					Required: true,
				},
			},
		},
	)
}

func registerProxier() {
	ngmodules.Register("tcp::proxier",
		func(spec *ngmodules.ArgNode) (any, error) {
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
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"hosts": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
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
	)
}

func registerProxyProtocolHandler() {
	ngmodules.Register("tcp::proxyprotocolhandler",
		func(spec *ngmodules.ArgNode) (any, error) {
			allowedSrcs := spec.MustGet("allowedsrcs").ToStringList()
			log.Debug().Strs("allowedsrcs", allowedSrcs).Msg("new tcp proxy protocol handler")
			return NewTCPProxyProtocolHandler(allowedSrcs), nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"allowedsrcs": {
					Type:    "list",
					Default: []*ngmodules.ArgNode{{Type: "string", Value: "127.0.0.1"}},
					Sub: ngmodules.AssertMap{
						"_": {Type: "string"},
					},
				},
			},
		},
	)
}
