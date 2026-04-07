package nghttp

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func (mid *Midware) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Routes: []ng.AdminRoute{
			{Method: "GET", Path: "/requests", Handler: func(ctx ng.AdminContext) {
				res, _ := mid.Report()
				ng.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
		},
		Root: ng.Widget{Content: ng.Table{
			Source: "requests",
			Poll:   "1s",
			Columns: []ng.ColumnDef{
				{Field: "method", Label: "Method", Type: "string"},
				{Field: "host", Label: "Host", Type: "string"},
				{Field: "uri", Label: "URI", Type: "string"},
				{Field: "code", Label: "Code", Type: "number"},
				{Field: "src", Label: "Source", Type: "string"},
				{Field: "protocol", Label: "Proto", Type: "string"},
				{Field: "respwritten", Label: "Written", Type: "bytes"},
				{Field: "enc", Label: "Encoding", Type: "string"},
				{Field: "starttime", Label: "Started", Type: "datetime"},
			},
		}},
	}
}

var _ ng.AdminProvider = (*Midware)(nil)
