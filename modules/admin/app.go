package ui

import (
	"errors"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/modules/tls"
	"github.com/mrhaoxx/OpenNG/pkg/log"
)

func init() {
	registerWebUI()
	registerSSELogger()
}

func registerWebUI() {
	ng.Register("webui",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"tcpcontroller": {Type: "ptr", Impls: []reflect.Type{}, Required: true},
				"httpmidware": {Type: "ptr",
					Impls:    []reflect.Type{ng.TypeOf[http.Midware]()},
					Struct:   true,
					Required: true},
				"tls": {Type: "ptr"},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[http.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			tcpController := spec.MustGet("tcpcontroller").Value.(Reporter)
			httpMidware := spec.MustGet("httpmidware").Value.(Reporter)

			ui := &UI{TcpController: tcpController, HttpMidware: httpMidware}

			if tlsArg, exists := spec.Get("tls"); exists == nil {
				tlsMgr, ok := tlsArg.Value.(*tls.TlsMgr)
				if !ok {
					return nil, errors.New("tls ptr is not a tls.TlsMgr")
				}
				ui.TlsMgr = tlsMgr
			}

			return ui, nil
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
