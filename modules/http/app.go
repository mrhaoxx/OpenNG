package http

import (
	"errors"
	"net/url"
	"reflect"

	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/dns"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog/log"
)

func init() {
	registerReverseProxier()
	registerMidware()
	registerMidwareAddService()
	registerSecureHTTP()
}

func registerReverseProxier() {
	ng.Register("http::reverseproxier",
		ng.Assert{
			Type:     "map",
			Required: true,
			Desc:     "HTTP reverse proxy configuration",
			Sub: ng.AssertMap{
				"hosts": {
					Type: "list",
					Desc: "reverse proxy host configurations",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {
									Type:     "string",
									Required: true,
									Desc:     "name of the proxy configuration",
								},
								"hosts": {
									Type:     "list",
									Required: true,
									Desc:     "hostnames to match for this proxy",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
								"backend": {
									Type:     "url",
									Required: true,
									Desc:     "backend URL to proxy requests to",
									Default:  &ngnet.URL{URL: url.URL{Scheme: "tcp"}, Interface: "sys"},
								},
								"MaxConnsPerHost": {
									Type:    "int",
									Default: 0,
									Desc:    "maximum concurrent connections per backend host",
								},
								"TlsSkipVerify": {
									Type:    "bool",
									Default: false,
									Desc:    "skip TLS certificate verification for backend",
								},
								"BypassEncoding": {
									Type:    "bool",
									Default: false,
									Desc:    "bypass encoding for backend",
								},
							},
						},
					},
				},
				"allowhosts": {
					Type:    "list",
					Default: []*ng.ArgNode{{Type: "hostname", Value: "*"}},
					Desc:    "hostnames that this proxy will handle",
					Sub: ng.AssertMap{
						"_": {Type: "hostname"},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.Iface[Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			hosts := spec.MustGet("hosts").ToList()
			allowedHosts := spec.MustGet("allowhosts").ToStringList()

			proxier := NewHTTPProxier(allowedHosts)

			for id, host := range hosts {
				name := host.MustGet("name").ToString()
				hostnames := host.MustGet("hosts").ToStringList()
				backend := host.MustGet("backend").ToURL()
				maxConns := host.MustGet("MaxConnsPerHost").ToInt()
				tlsSkip := host.MustGet("TlsSkipVerify").ToBool()
				bypassEncoding := host.MustGet("BypassEncoding").ToBool()

				if err := proxier.Insert(id, name, hostnames, backend, maxConns, tlsSkip, bypassEncoding); err != nil {
					return nil, err
				}

				log.Debug().
					Str("name", name).
					Strs("hosts", hostnames).
					Str("backend", backend.String()).
					Int("maxconns", maxConns).
					Bool("tlsskip", tlsSkip).
					Bool("bypassencoding", bypassEncoding).
					Msg("new http reverse host")
			}

			return proxier, nil
		},
	)
}

func registerMidware() {
	ng.Register("http::midware",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"services": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {Type: "string", Required: true},
								"logi": {Type: "ptr", Required: true, Impls: []reflect.Type{ng.Iface[Service]()}, Desc: "pointer to service function"},
								"hosts": {
									Type: "list",
									Desc: "hostnames this service handles",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
							},
						},
					},
				},
				"cgis": {
					Type:    "list",
					Default: []*ng.ArgNode{},
					Desc:    "CGI handlers for /ng-cgi/* paths",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"logi": {Type: "ptr", Required: true, Impls: []reflect.Type{ng.Iface[Cgi]()}, Desc: "pointer to CGI handler implementation"},
								"paths": {
									Type: "list",
									Desc: "URL paths this CGI handles",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
				"forward": {
					Type:    "list",
					Default: []*ng.ArgNode{},
					Desc:    "forward proxy handlers",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {Type: "string", Required: true, Desc: "name of the forward proxy handler"},
								"logi": {Type: "ptr", Required: true, Impls: []reflect.Type{ng.Iface[Forward]()}, Desc: "pointer to forward proxy implementation"},
								"hosts": {
									Type:    "list",
									Default: []*ng.ArgNode{{Type: "hostname", Value: "*"}},
									Desc:    "hostnames this forward proxy handles",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
							},
						},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.Iface[tcp.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			services := spec.MustGet("services").ToList()
			cgis := spec.MustGet("cgis").ToList()
			forwards := spec.MustGet("forward").ToList()

			midware := NewHttpMidware([]string{"*"})

			midware.AddCgis(&CgiStruct{
				CgiHandler: func(ctx *HttpCtx, path string) Ret {
					ctx.Resp.Header().Set("Content-Type", "image/svg+xml")
					ctx.Resp.Header().Set("Cache-Control", "max-age=2592000")
					ctx.Resp.Write(ng.Logo())

					return RequestEnd
				},
				CgiPaths: []*regexp2.Regexp{regexp2.MustCompile("^/logo$", regexp2.None)},
			})

			for _, srv := range services {
				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				hosts := srv.MustGet("hosts").ToStringList()

				service := logi.Value.(Service)

				var compiled groupexp.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.Hosts()
				} else {
					compiled = groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
				}

				midware.AddServices(&ServiceStruct{
					Id:             name,
					Hosts:          compiled,
					ServiceHandler: service.HandleHTTP,
				})

				log.Debug().
					Str("name", name).
					Strs("hosts", compiled.String()).
					Type("logi", logi.Value).
					Msg("new http service")
			}

			for _, cgi := range cgis {
				logi := cgi.MustGet("logi")

				service := logi.Value.(Cgi)

				midware.AddCgis(&CgiStruct{
					CgiHandler: service.HandleHTTPCgi,
					CgiPaths:   service.CgiPaths(),
				})

				log.Debug().
					Type("logi", logi.Value).
					Msg("new http cgi")
			}

			for _, fwd := range forwards {
				name := fwd.MustGet("name").ToString()
				logi := fwd.MustGet("logi")
				hosts := fwd.MustGet("hosts").ToStringList()

				service := logi.Value.(Forward)

				var compiled groupexp.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.HostsForward()
				} else {
					compiled = groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
				}

				midware.AddForwardServices(&ServiceStruct{
					Id:             name,
					Hosts:          compiled,
					ServiceHandler: service.HandleHTTPForward,
				})

				log.Debug().
					Str("name", name).
					Strs("hosts", compiled.String()).
					Type("logi", logi.Value).
					Msg("new http forward service")
			}

			return midware, nil
		},
	)
}

func registerMidwareAddService() {
	ng.Register("http::midware::addservice",
		ng.Assert{
			Type: "map",
			Desc: "adds additional HTTP services to an existing HTTP middleware",
			Sub: ng.AssertMap{
				"midware": {Type: "ptr", Required: true, Desc: "pointer to the target HTTP middleware to add services to"},
				"services": {
					Type: "list",
					Desc: "list of HTTP services to add",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"logi": {Type: "ptr", Required: true, Impls: []reflect.Type{ng.Iface[Service]()}, Desc: "pointer to service handler implementation"},
								"hosts": {
									Type: "list",
									Desc: "hostnames this service handles",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
								"name": {Type: "string", Required: true, Desc: "name of the service (used in logs and monitoring)"},
							},
						},
					},
				},
			},
		},
		ng.Assert{Type: "null"},
		func(spec *ng.ArgNode) (any, error) {
			midware, ok := spec.MustGet("midware").Value.(*Midware)
			if !ok {
				return nil, errors.New("ptr is not a http.Midware")
			}

			services := spec.MustGet("services").ToList()

			for _, srv := range services {
				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				hosts := srv.MustGet("hosts").ToStringList()

				service := logi.Value.(Service)

				var compiled groupexp.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.Hosts()
				} else {
					compiled = groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
				}

				midware.AddServices(&ServiceStruct{
					Id:             name,
					Hosts:          compiled,
					ServiceHandler: service.HandleHTTP,
				})

				log.Debug().
					Str("name", name).
					Strs("hosts", compiled.String()).
					Type("logi", logi.Value).
					Msg("new http service")
			}

			return nil, nil
		},
	)
}

func registerSecureHTTP() {
	ng.Register("tcp::securehttp",
		ng.Assert{Type: "null"},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.Iface[tcp.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			return Redirect2TLS, nil
		},
	)
}
