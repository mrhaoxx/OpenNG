package tcp

import (
	"errors"
	"net/url"
	"reflect"
	"time"

	ng "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
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
	ng.Register("tcp::det",
		ng.Assert{
			Type:     "map",
			Required: true,
			Sub: ng.AssertMap{
				"protocols": {
					Type: "list",
					Sub: ng.AssertMap{
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
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
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
		},
	)
}

func registerController() {
	ng.Register("tcp::controller",
		ng.Assert{
			Type:     "map",
			Required: true,
			Desc:     "TCP connection controller that manages protocol detection and service routing",
			Sub: ng.AssertMap{
				"services": {
					Type: "map",
					Desc: "protocol-specific service handlers, where key is the protocol name (e.g. '' (first inbound), 'TLS', 'HTTP1', 'TLS HTTP2', etc)",
					Sub: ng.AssertMap{
						"_": {
							Type: "list",
							Desc: "ordered list of service handlers for each protocol",
							Sub: ng.AssertMap{
								"_": {
									Type: "map",
									Sub: ng.AssertMap{
										"name": {
											Type:     "string",
											Required: true,
											Desc:     "name of the service handler (used in connection logs)",
										},
										"logi": {
											Type:     "ptr",
											Required: true,
											Desc:     "pointer to service",
											Impls: []reflect.Type{
												ng.TypeOf[Service](),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		ng.Assert{Type: "ptr"},
		func(spec *ng.ArgNode) (any, error) {
			services := spec.MustGet("services").ToMap()

			controller := NewTcpController()

			for name, srvs := range services {
				var bindings []ServiceBinding
				for i, srv := range srvs.ToList() {
					serviceName := srv.MustGet("name").ToString()
					logi := srv.MustGet("logi")
					service := logi.Value.(Service)

					bindings = append(bindings, ServiceBinding{
						Name:    serviceName,
						Service: service,
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
		},
	)
}

func registerListener() {
	ng.Register("tcp::listen",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"AddressBindings": {
					Type: "list",
					Desc: "tcp listen address",
					Sub: ng.AssertMap{
						"_": {Type: "string", Enum: []any{"0.0.0.0:443", "0.0.0.0:80", "0.0.0.0:22"}, AllowNonEnum: true},
					},
				},
				"ptr": {
					Type:     "ptr",
					Required: true,
				},
			},
		},
		ng.Assert{Type: "null"},
		func(spec *ng.ArgNode) (any, error) {
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
		},
	)
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
