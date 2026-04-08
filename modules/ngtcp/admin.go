package ngtcp

import (
	w "github.com/mrhaoxx/OpenNG/modules/admin/widget"
)

func (ctl *Controller) AdminMeta() w.AdminMeta {
	return w.AdminMeta{
		Routes: []w.AdminRoute{
			{Method: "GET", Path: "/connections", Handler: func(ctx w.AdminContext) {
				res, _ := ctl.Report()
				w.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
			{Method: "GET", Path: "/stats", Handler: func(ctx w.AdminContext) {
				w.WriteJSON(ctx.ResponseWriter(), 200, map[string]any{
					"totalConns":  ctl.TotalConns.Load(),
					"activeConns": ctl.ActiveConns.Load(),
					"totalRx":     ctl.TotalRx.Load(),
					"totalTx":     ctl.TotalTx.Load(),
					"connRate5s":  ctl.ConnRate.Rate(5),
					"connRate60s": ctl.ConnRate.Rate(59),
				})
			}},
		},
		Root: w.Column(1,
			w.Row(
				w.Widget{Content: w.Stat{Label: "Total Connections", Source: "stats", Field: "totalConns", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "Active", Source: "stats", Field: "activeConns", Poll: "1s"}},
				w.Widget{Content: w.Stat{Label: "Conn/s (5s)", Source: "stats", Field: "connRate5s", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "Total RX", Source: "stats", Field: "totalRx", Unit: "bytes", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "Total TX", Source: "stats", Field: "totalTx", Unit: "bytes", Poll: "2s"}},
			),
			w.Widget{Content: w.Table{
				Source: "connections",
				Poll:   "1s",
				Columns: []w.ColumnDef{
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

var _ w.AdminProvider = (*Controller)(nil)
