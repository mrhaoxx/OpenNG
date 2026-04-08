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
			{Method: "GET", Path: "/stats", Handler: func(ctx ng.AdminContext) {
				ng.WriteJSON(ctx.ResponseWriter(), 200, map[string]any{
					"totalConns":  ctl.TotalConns.Load(),
					"activeConns": ctl.ActiveConns.Load(),
					"totalRx":     ctl.TotalRx.Load(),
					"totalTx":     ctl.TotalTx.Load(),
					"connRate5s":  ctl.ConnRate.Rate(5),
					"connRate60s": ctl.ConnRate.Rate(59),
				})
			}},
		},
		Root: ng.Column(1,
			ng.Row(
				ng.Widget{Content: ng.Stat{Label: "Total Connections", Source: "stats", Field: "totalConns", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "Active", Source: "stats", Field: "activeConns", Poll: "1s"}},
				ng.Widget{Content: ng.Stat{Label: "Conn/s (5s)", Source: "stats", Field: "connRate5s", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "Total RX", Source: "stats", Field: "totalRx", Unit: "bytes", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "Total TX", Source: "stats", Field: "totalTx", Unit: "bytes", Poll: "2s"}},
			),
			ng.Widget{Content: ng.Table{
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
		),
	}
}

var _ ng.AdminProvider = (*Controller)(nil)
