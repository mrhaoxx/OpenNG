package ngtcp

import (
	"github.com/mrhaoxx/OpenNG/modules/admin/admeta"
)

func (ctl *Controller) AdminMeta() admeta.AdminMeta {
	return admeta.AdminMeta{
		Routes: []admeta.AdminRoute{
			{Method: "GET", Path: "/connections", Handler: func(ctx admeta.AdminContext) {
				res, _ := ctl.Report()
				admeta.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
			{Method: "GET", Path: "/stats", Handler: func(ctx admeta.AdminContext) {
				admeta.WriteJSON(ctx.ResponseWriter(), 200, map[string]any{
					"totalConns":  ctl.TotalConns.Load(),
					"activeConns": ctl.ActiveConns.Load(),
					"totalRx":     ctl.TotalRx.Load(),
					"totalTx":     ctl.TotalTx.Load(),
					"connRate5s":  ctl.ConnRate.Rate(5),
					"connRate60s": ctl.ConnRate.Rate(59),
				})
			}},
		},
		Root: admeta.Column(1,
			admeta.Row(
				admeta.Widget{Content: admeta.Stat{Label: "Total Connections", Source: "stats", Field: "totalConns", Poll: "2s"}},
				admeta.Widget{Content: admeta.Stat{Label: "Active", Source: "stats", Field: "activeConns", Poll: "1s"}},
				admeta.Widget{Content: admeta.Stat{Label: "Conn/s (5s)", Source: "stats", Field: "connRate5s", Poll: "2s"}},
				admeta.Widget{Content: admeta.Stat{Label: "Total RX", Source: "stats", Field: "totalRx", Unit: "bytes", Poll: "2s"}},
				admeta.Widget{Content: admeta.Stat{Label: "Total TX", Source: "stats", Field: "totalTx", Unit: "bytes", Poll: "2s"}},
			),
			admeta.Widget{Content: admeta.Table{
				Source: "connections",
				Poll:   "1s",
				Columns: []admeta.ColumnDef{
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

var _ admeta.AdminProvider = (*Controller)(nil)
