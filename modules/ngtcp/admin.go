package ngtcp

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func (ctl *Controller) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Routes: []ng.AdminRoute{
			{Method: "GET", Path: "/connections", Handler: func(ctx ng.AdminContext) {
				res, _ := ctl.Report()
				ng.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
		},
		Root: ng.Widget{Content: ng.Table{
			Source: "connections",
			Poll:   "1s",
			Columns: []ng.ColumnDef{
				{Field: "src", Label: "Source", Type: "string"},
				{Field: "protocols", Label: "Protocols", Type: "string"},
				{Field: "path", Label: "Path", Type: "string"},
				{Field: "bytesrx", Label: "RX", Type: "bytes"},
				{Field: "bytestx", Label: "TX", Type: "bytes"},
				{Field: "starttime", Label: "Started", Type: "datetime"},
			},
		}},
	}
}

var _ ng.AdminProvider = (*Controller)(nil)
