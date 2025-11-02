package http

import (
	netgate "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	netgate.Register("http::proxy",
		func(spec *netgate.ArgNode) (any, error) {
			proxyURL := spec.MustGet("url").ToURL()
			return &HttpProxyInterface{Proxyurl: proxyURL}, nil
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"url": {
					Type:     "url",
					Required: true,
					Default:  &opennet.URL{Interface: "sys"},
				},
			},
		},
	)
	netgate.Register("http::forwardproxier",
		func(spec *netgate.ArgNode) (any, error) {
			underlying := spec.MustGet("interface").Value.(opennet.Interface)
			return &StdForwardProxy{Underlying: underlying}, nil
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
	)
}
