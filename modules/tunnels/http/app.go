package http

import (
	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	opennet "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	ngmodules.Register("http::proxy",
		func(spec *ngmodules.ArgNode) (any, error) {
			proxyURL := spec.MustGet("url").ToURL()
			return &HttpProxyInterface{Proxyurl: proxyURL}, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"url": {
					Type:     "url",
					Required: true,
					Default:  &opennet.URL{Interface: "sys"},
				},
			},
		},
	)
	ngmodules.Register("http::forwardproxier",
		func(spec *ngmodules.ArgNode) (any, error) {
			underlying := spec.MustGet("interface").Value.(opennet.Interface)
			return &StdForwardProxy{Underlying: underlying}, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
	)
}
