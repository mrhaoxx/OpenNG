package ui

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/log"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
)

func init() {
	ng.Register("webui",
		ng.Assert{
			Type: "null",
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[nghttp.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			log.Loggers.Add(Sselogger)
			return &UI{}, nil
		})
}
