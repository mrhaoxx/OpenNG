package ui

import (
	"errors"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/tls"
	"github.com/mrhaoxx/OpenNG/utils"
)

var _builtin_refs_assertions = map[string]Assert{
	"_": {
		Type: "map",
		Sub: AssertMap{
			"Services": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {Type: "string", Required: true},
							"kind": {Type: "string", Required: true},
							"spec": {Type: "any"},
						},
					},
				},
			},
			"version": {
				Type:     "int",
				Required: true,
				Default:  5,
			},
			"Config": {
				Type: "map",
				Sub: AssertMap{
					"Logger": {
						Type: "map",
						Sub: AssertMap{
							"EnableSSE": {
								Type:    "bool",
								Default: false,
							},
						},
					},
				},
			},
		},
	},
	"builtin::http::proxier": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"hosts": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
							},
							"hosts": {
								Type:     "list",
								Required: true,
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
							"backend": {
								Type:     "string",
								Required: true,
							},
							"MaxConnsPerHost": {
								Type:    "int",
								Default: 0,
							},
							"TlsSkipVerify": {
								Type:    "bool",
								Default: false,
							},
						},
					},
				},
			},
			"allowhosts": {
				Type:    "list",
				Default: []*ArgNode{{Type: "string", Value: "*"}},
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
		},
	},
	"builtin::tls": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"certificates": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"CertFile": {
								Type:     "string",
								Required: true,
							},
							"KeyFile": {
								Type:     "string",
								Required: true,
							},
						},
					},
				},
			},
		},
	},
	"builtin::http::midware": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"services": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"logi": {
								Type:     "ptr",
								Required: true,
							},
							"hosts": {
								Type: "list",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
							"name": {
								Type:     "string",
								Required: true,
							},
						},
					},
				},
			},
		},
	},
	"builtin::tcp::det": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"protocols": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "string",
					},
				},
			},
		},
	},
	"builtin::tcp::controller": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"AddressBindings": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "string",
					},
				},
			},
			"services": {
				Type: "map",
				Sub: AssertMap{
					"_": {
						Type: "list",
						Sub: AssertMap{
							"_": {
								Type: "map",
								Sub: AssertMap{
									"name": {
										Type:     "string",
										Required: true,
									},
									"logi": {
										Type:     "ptr",
										Required: true,
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

var _builtin_refs = map[string]Inst{
	"builtin::http::proxier": func(spec *ArgNode) (any, error) {
		hosts := spec.MustGet("hosts").ToList()

		allowedhosts := spec.MustGet("allowhosts").ToStringList()

		proxier := http.NewHTTPProxier(allowedhosts)

		for _, host := range hosts {
			name := host.MustGet("name").ToString()
			hosts := host.MustGet("hosts").ToStringList()

			backend := host.MustGet("backend").ToString()
			maxconns := host.MustGet("MaxConnsPerHost").ToInt()
			tlsskip := host.MustGet("TlsSkipVerify").ToBool()

			proxier.Insert(proxier.Len(), name, hosts, backend, maxconns, tlsskip)

			log.Println("sys", "http", name, "->", hosts, backend, maxconns, tlsskip)
		}

		return proxier, nil
	},
	"builtin::tls": func(spec *ArgNode) (any, error) {
		certs := spec.MustGet("certificates").ToList()

		tls := tls.NewTlsMgr()

		for _, cert := range certs {
			certfile := cert.MustGet("CertFile").ToString()
			keyfile := cert.MustGet("KeyFile").ToString()

			tls.LoadCertificate(certfile, keyfile)

			log.Println("sys", "tls", certfile, keyfile)
		}

		return tls, nil
	},
	"builtin::http::midware": func(spec *ArgNode) (any, error) {
		services := spec.MustGet("services").ToList()

		var midware = http.NewHttpMidware([]string{"*"})

		for _, srv := range services {
			name := srv.MustGet("name").ToString()
			logi := srv.MustGet("logi")
			_hosts := srv.MustGet("hosts").ToStringList()

			var hosts []*regexp2.Regexp
			service, ok := logi.Value.(http.Service)
			if !ok {
				return nil, errors.New("ptr " + name + " is not a http.Service")
			}
			if len(_hosts) == 0 {
				hosts = service.Hosts()
			} else {
				hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(_hosts))
			}

			midware.AddServices(&http.ServiceStruct{
				Id:             name,
				Hosts:          hosts,
				ServiceHandler: service.HandleHTTP,
			})

			log.Println("sys", "http", name, "->", hosts, logi.Value)
		}

		return midware, nil
	},
	"builtin::tcp::det": func(spec *ArgNode) (any, error) {
		protocols := spec.MustGet("protocols").ToStringList()

		var dets []tcp.Detector
		for _, p := range protocols {
			switch p {
			case "tls":
				dets = append(dets, tcp.DetectTLS)
			case "proxyprotocol":
				dets = append(dets, tcp.DetectPROXYPROTOCOL)
			case "ssh":
				dets = append(dets, tcp.DetectSSH)
			case "rdp":
				dets = append(dets, tcp.DetectRDP)
			case "http":
				dets = append(dets, tcp.DetectHTTP)
			default:
				return nil, errors.New("unknown protocol: " + p)
			}
		}

		return &tcp.Detect{Dets: dets}, nil
	},
	"builtin::tcp::controller": func(spec *ArgNode) (any, error) {
		addrs := spec.MustGet("AddressBindings").ToStringList()
		services := spec.MustGet("services").ToMap()

		controller := tcp.NewTcpController()

		for name, srvs := range services {
			var _bindings []tcp.ServiceBinding
			for _, srv := range srvs.ToList() {

				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				service, ok := logi.Value.(tcp.ServiceHandler)
				if !ok {
					return nil, errors.New("ptr " + name + " is not a tcp.ServiceHandler")
				}
				_bindings = append(_bindings, tcp.ServiceBinding{
					Name:           name,
					ServiceHandler: service,
				})

			}

			controller.Bind(name, _bindings...)

			log.Println("sys", "tcp", name, "->", services)

		}

		for _, addr := range addrs {
			controller.Listen(addr)
		}

		return controller, nil
	},
}
