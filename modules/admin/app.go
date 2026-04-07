package ui

import (
	"errors"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	ngcmd "github.com/mrhaoxx/OpenNG/cmd"
	"github.com/mrhaoxx/OpenNG/modules/log"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
	"github.com/mrhaoxx/OpenNG/modules/ngtls"
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
					Impls:    []reflect.Type{ng.TypeOf[nghttp.Midware]()},
					Struct:   true,
					Required: true},
				"tls": {Type: "ptr"},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[nghttp.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			tcpController := spec.MustGet("tcpcontroller").Value.(Reporter)
			httpMidware := spec.MustGet("httpmidware").Value.(Reporter)

			ui := &UI{TcpController: tcpController, HttpMidware: httpMidware}

			if tlsArg, exists := spec.Get("tls"); exists == nil {
				tlsMgr, ok := tlsArg.Value.(*ngtls.TlsMgr)
				if !ok {
					return nil, errors.New("tls ptr is not a tls.TlsMgr")
				}
				ui.TlsMgr = tlsMgr
			}

			if ngcmd.CurSpace != nil {
				ui.DiscoverProviders(ngcmd.CurSpace.Services)
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
