package http

import (
	"errors"
	"net/url"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/config"
	"github.com/mrhaoxx/OpenNG/core"
	"github.com/mrhaoxx/OpenNG/modules/dns"
	opennet "github.com/mrhaoxx/OpenNG/net"
	"github.com/mrhaoxx/OpenNG/utils"
	"github.com/rs/zerolog/log"
)

func init() {
	registerReverseProxier()
	registerMidware()
	registerMidwareAddService()
	registerSecureHTTP()
}

func registerReverseProxier() {
	config.Register("http::reverseproxier",
		func(spec *config.ArgNode) (any, error) {
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
		}, config.Assert{
			Type:     "map",
			Required: true,
			Desc:     "HTTP reverse proxy configuration",
			Sub: config.AssertMap{
				"hosts": {
					Type: "list",
					Desc: "reverse proxy host configurations",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
								"name": {
									Type:     "string",
									Required: true,
									Desc:     "name of the proxy configuration",
								},
								"hosts": {
									Type:     "list",
									Required: true,
									Desc:     "hostnames to match for this proxy",
									Sub: config.AssertMap{
										"_": {Type: "hostname", Desc: config.DescHostnameFormat},
									},
								},
								"backend": {
									Type:     "url",
									Required: true,
									Desc:     "backend URL to proxy requests to",
									Default:  &opennet.URL{URL: url.URL{Scheme: "tcp"}, Interface: "sys"},
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
					Default: []*config.ArgNode{{Type: "hostname", Value: "*"}},
					Desc:    "hostnames that this proxy will handle",
					Sub: config.AssertMap{
						"_": {Type: "hostname", Desc: config.DescHostnameFormat},
					},
				},
			},
		},
	)
}

func registerMidware() {
	config.Register("http::midware",
		func(spec *config.ArgNode) (any, error) {
			services := spec.MustGet("services").ToList()
			cgis := spec.MustGet("cgis").ToList()
			forwards := spec.MustGet("forward").ToList()

			midware := NewHttpMidware([]string{"*"})

			midware.AddCgis(&CgiStruct{
				CgiHandler: func(ctx *HttpCtx, path string) Ret {
					ctx.Resp.Header().Set("Content-Type", "image/svg+xml")
					ctx.Resp.Header().Set("Cache-Control", "max-age=2592000")
					ctx.Resp.Write(core.Logo())

					return RequestEnd
				},
				CgiPaths: []*regexp2.Regexp{regexp2.MustCompile("^/logo$", regexp2.None)},
			})

			for _, srv := range services {
				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				hosts := srv.MustGet("hosts").ToStringList()

				service, ok := logi.Value.(Service)
				if !ok {
					return nil, errors.New("ptr " + name + " is not a http.Service")
				}

				var compiled utils.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.Hosts()
				} else {
					compiled = utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
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

				service, ok := logi.Value.(Cgi)
				if !ok {
					return nil, errors.New("ptr is not a http.Cgi")
				}

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

				service, ok := logi.Value.(Forward)
				if !ok {
					return nil, errors.New("ptr " + name + " is not a http.Forward")
				}

				var compiled utils.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.HostsForward()
				} else {
					compiled = utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
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
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"services": {
					Type: "list",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
								"name": {Type: "string", Required: true},
								"logi": {Type: "ptr", Required: true, Desc: "pointer to service function"},
								"hosts": {
									Type: "list",
									Desc: "hostnames this service handles",
									Sub: config.AssertMap{
										"_": {Type: "hostname", Desc: config.DescHostnameFormat},
									},
								},
							},
						},
					},
				},
				"cgis": {
					Type:    "list",
					Default: []*config.ArgNode{},
					Desc:    "CGI handlers for /ng-cgi/* paths",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
								"logi": {Type: "ptr", Required: true, Desc: "pointer to CGI handler implementation"},
								"paths": {
									Type: "list",
									Desc: "URL paths this CGI handles",
									Sub: config.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
				"forward": {
					Type:    "list",
					Default: []*config.ArgNode{},
					Desc:    "forward proxy handlers",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
								"name": {Type: "string", Required: true, Desc: "name of the forward proxy handler"},
								"logi": {Type: "ptr", Required: true, Desc: "pointer to forward proxy implementation"},
								"hosts": {
									Type:    "list",
									Default: []*config.ArgNode{{Type: "hostname", Value: "*"}},
									Desc:    "hostnames this forward proxy handles",
									Sub: config.AssertMap{
										"_": {Type: "hostname", Desc: config.DescHostnameFormat},
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

func registerMidwareAddService() {
	config.Register("http::midware::addservice",
		func(spec *config.ArgNode) (any, error) {
			midware, ok := spec.MustGet("midware").Value.(*Midware)
			if !ok {
				return nil, errors.New("ptr is not a http.Midware")
			}

			services := spec.MustGet("services").ToList()

			for _, srv := range services {
				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				hosts := srv.MustGet("hosts").ToStringList()

				service, ok := logi.Value.(Service)
				if !ok {
					return nil, errors.New("ptr " + name + " is not a http.Service")
				}

				var compiled utils.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.Hosts()
				} else {
					compiled = utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
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
		}, config.Assert{
			Type: "map",
			Desc: "adds additional HTTP services to an existing HTTP middleware",
			Sub: config.AssertMap{
				"midware": {Type: "ptr", Required: true, Desc: "pointer to the target HTTP middleware to add services to"},
				"services": {
					Type: "list",
					Desc: "list of HTTP services to add",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
								"logi": {Type: "ptr", Required: true, Desc: "pointer to service handler implementation"},
								"hosts": {
									Type: "list",
									Desc: "hostnames this service handles",
									Sub: config.AssertMap{
										"_": {Type: "hostname", Desc: config.DescHostnameFormat},
									},
								},
								"name": {Type: "string", Required: true, Desc: "name of the service (used in logs and monitoring)"},
							},
						},
					},
				},
			},
		},
	)
}

func registerSecureHTTP() {
	config.Register("tcp::securehttp",
		func(spec *config.ArgNode) (any, error) {
			return Redirect2TLS, nil
		}, config.Assert{Type: "null"},
	)
}
