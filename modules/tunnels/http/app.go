package http

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	httpsdk "github.com/mrhaoxx/OpenNG/modules/nghttp"
	opennet "github.com/mrhaoxx/OpenNG/modules/ngnet"
)

func init() {
	ng.Register("http::proxy",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"url": {
					Type:     "url",
					Required: true,
					Default:  &opennet.URL{Interface: "sys"},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[opennet.Interface](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			proxyURL := spec.MustGet("url").ToURL()
			return &HttpProxyInterface{Proxyurl: proxyURL}, nil
		},
	)
	ng.Register("http::forwardproxier",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[httpsdk.Forward](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			underlying := spec.MustGet("interface").Value.(opennet.Interface)
			return &StdForwardProxy{Underlying: underlying}, nil
		},
	)
}
