package ui

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/log"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
)

func init() {
	registerWebUI()
	registerSSELogger()
}

func registerWebUI() {
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
			return &UI{}, nil
		})
}

func registerSSELogger() {
	ng.Register("webui::sselog",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.TypeOf[log.Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			return Sselogger, nil
		})
}
