package nghttp

import (
	"net/url"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	tcpsdk "github.com/mrhaoxx/OpenNG/modules/ngtcp"
)

func init() {
	registerReverseProxier()
	registerMidware()
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
