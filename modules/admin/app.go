package ui

import (
	"errors"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/tls"
)

func init() {
	registerWebUI()
	registerSSELogger()
}

func registerWebUI() {
	ng.Register("webui",
		func(spec *ng.ArgNode) (any, error) {
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
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"tcpcontroller": {Type: "ptr", Required: true},
				"httpmidware":   {Type: "ptr", Required: true},
				"tls":           {Type: "ptr"},
			},
		},
	)
}

func registerSSELogger() {
	ng.Register("webui::sselog", func(an *ng.ArgNode) (any, error) {
		return Sselogger, nil
	}, ng.Assert{
		Type: "null",
	})
}
