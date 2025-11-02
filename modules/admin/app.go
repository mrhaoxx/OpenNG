package ui

import (
	"errors"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	"github.com/mrhaoxx/OpenNG/modules/tls"
)

func init() {
	registerWebUI()
	registerSSELogger()
}

func registerWebUI() {
	ngmodules.Register("webui",
		func(spec *ngmodules.ArgNode) (any, error) {
			tcpController, ok := spec.MustGet("tcpcontroller").Value.(Reporter)
			if !ok {
				return nil, errors.New("tcp controller ptr is not a Reporter")
			}
			httpMidware, ok := spec.MustGet("httpmidware").Value.(Reporter)
			if !ok {
				return nil, errors.New("http midware ptr is not a Reporter")
			}

			ui := &UI{TcpController: tcpController, HttpMidware: httpMidware}

			if tlsArg, exists := spec.Get("tls"); exists == nil {
				tlsMgr, ok := tlsArg.Value.(*tls.TlsMgr)
				if !ok {
					return nil, errors.New("tls ptr is not a tls.TlsMgr")
				}
				ui.TlsMgr = tlsMgr
			}

			return ui, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"tcpcontroller": {Type: "ptr", Required: true},
				"httpmidware":   {Type: "ptr", Required: true},
				"tls":           {Type: "ptr"},
			},
		},
	)
}

func registerSSELogger() {
	ngmodules.Register("webui::sselog", func(an *ngmodules.ArgNode) (any, error) {
		return Sselogger, nil
	}, ngmodules.Assert{
		Type: "null",
	})
}
