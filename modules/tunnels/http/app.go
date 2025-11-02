package http

import (
	"github.com/mrhaoxx/OpenNG/config"
	opennet "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	config.Register("http::proxy",
		func(spec *config.ArgNode) (any, error) {
			proxyURL := spec.MustGet("url").ToURL()
			return &HttpProxyInterface{Proxyurl: proxyURL}, nil
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"url": {
					Type:     "url",
					Required: true,
					Default:  &opennet.URL{Interface: "sys"},
				},
			},
		},
	)
	config.Register("http::forwardproxier",
		func(spec *config.ArgNode) (any, error) {
			underlying := spec.MustGet("interface").Value.(opennet.Interface)
			return &StdForwardProxy{Underlying: underlying}, nil
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
	)
}
