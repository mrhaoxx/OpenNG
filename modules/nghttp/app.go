package nghttp

import (
	"errors"
	"net/url"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/groupexp"
	"github.com/mrhaoxx/OpenNG/modules/ngnet"
	tcpsdk "github.com/mrhaoxx/OpenNG/modules/ngtcp"
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
				ng.TypeOf[Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			hosts := spec.MustGet("hosts").ToList()
			allowedHosts := spec.MustGet("allowhosts").ToGroupRegexp()

			proxier := NewHTTPProxier(allowedHosts)

			for id, host := range hosts {
				name := host.MustGet("name").ToString()
				hostnames := host.MustGet("hosts").ToGroupRegexp()
				backend := host.MustGet("backend").ToURL()
				maxConns := host.MustGet("MaxConnsPerHost").ToInt()
				tlsSkip := host.MustGet("TlsSkipVerify").ToBool()
				bypassEncoding := host.MustGet("BypassEncoding").ToBool()

				if err := proxier.Insert(id, name, hostnames, backend, maxConns, tlsSkip, bypassEncoding); err != nil {
					return nil, err
				}
			}

			return proxier, nil
		},
	)
}

func registerMidware() {
	ng.RegisterFunc("http::midware", NewHttpMidware)
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
								"logi": {Type: "ptr", Required: true, Impls: []reflect.Type{ng.TypeOf[Service]()}, Desc: "pointer to service handler implementation"},
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
				hosts := srv.MustGet("hosts").ToGroupRegexp()

				service := logi.Value.(Service)

				var compiled groupexp.GroupRegexp
				if len(hosts) == 0 {
					compiled = service.Hosts()
				} else {
					compiled = hosts
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
				ng.TypeOf[tcpsdk.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			return Redirect2TLS, nil
		},
	)
}
