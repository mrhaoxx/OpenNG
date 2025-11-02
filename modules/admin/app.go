package ui

import (
	"errors"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/tls"
)

func init() {
	registerWebUI()
}

func registerWebUI() {
	netgate.Register("webui",
		func(spec *netgate.ArgNode) (any, error) {
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
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"tcpcontroller": {Type: "ptr", Required: true},
				"httpmidware":   {Type: "ptr", Required: true},
				"tls":           {Type: "ptr"},
			},
		},
	)
}
