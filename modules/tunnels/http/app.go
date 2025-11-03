package http

import (
	ng "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	ng.Register("http::proxy",
		func(spec *ng.ArgNode) (any, error) {
			proxyURL := spec.MustGet("url").ToURL()
			return &HttpProxyInterface{Proxyurl: proxyURL}, nil
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"url": {
					Type:     "url",
					Required: true,
					Default:  &opennet.URL{Interface: "sys"},
				},
			},
		},
	)
	ng.Register("http::forwardproxier",
		func(spec *ng.ArgNode) (any, error) {
			underlying := spec.MustGet("interface").Value.(opennet.Interface)
			return &StdForwardProxy{Underlying: underlying}, nil
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
	)
}
