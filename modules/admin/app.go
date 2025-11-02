package ui

import (
	"errors"

	"github.com/mrhaoxx/OpenNG/config"
	"github.com/mrhaoxx/OpenNG/modules/tls"
)

func init() {
	registerWebUI()
	registerSSELogger()
}

func registerWebUI() {
	config.Register("webui",
		func(spec *config.ArgNode) (any, error) {
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
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"tcpcontroller": {Type: "ptr", Required: true},
				"httpmidware":   {Type: "ptr", Required: true},
				"tls":           {Type: "ptr"},
			},
		},
	)
}

func registerSSELogger() {
	netgate.Register("webui::sselog", func(an *netgate.ArgNode) (any, error) {
		return Sselogger, nil
	}, netgate.Assert{
		Type: "null",
	})
}
