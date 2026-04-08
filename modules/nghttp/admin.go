package nghttp

import (
	w "github.com/mrhaoxx/OpenNG/modules/admin/widget"
)

func (mid *Midware) AdminMeta() w.AdminMeta {
	return w.AdminMeta{
		Routes: []w.AdminRoute{
			{Method: "GET", Path: "/requests", Handler: func(ctx w.AdminContext) {
				res, _ := mid.Report()
				w.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
			{Method: "GET", Path: "/stats", Handler: func(ctx w.AdminContext) {
				w.WriteJSON(ctx.ResponseWriter(), 200, map[string]any{
					"totalRequests":  mid.TotalRequests.Load(),
					"activeRequests": mid.ActiveRequests.Load(),
					"totalBytesOut":  mid.TotalBytesOut.Load(),
					"status2xx":      mid.StatusBucket.Load(2),
					"status3xx":      mid.StatusBucket.Load(3),
					"status4xx":      mid.StatusBucket.Load(4),
					"status5xx":      mid.StatusBucket.Load(5),
					"reqRate5s":      mid.ReqRate.Rate(5),
					"reqRate60s":     mid.ReqRate.Rate(59),
				})
			}},
		},
		Root: w.Column(1,
			w.Row(
				w.Widget{Content: w.Stat{Label: "Total Requests", Source: "stats", Field: "totalRequests", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "Active", Source: "stats", Field: "activeRequests", Poll: "1s"}},
				w.Widget{Content: w.Stat{Label: "Req/s (5s)", Source: "stats", Field: "reqRate5s", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "Total TX", Source: "stats", Field: "totalBytesOut", Unit: "bytes", Poll: "2s"}},
			),
			w.Row(
				w.Widget{Content: w.Stat{Label: "2xx", Source: "stats", Field: "status2xx", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "3xx", Source: "stats", Field: "status3xx", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "4xx", Source: "stats", Field: "status4xx", Poll: "2s"}},
				w.Widget{Content: w.Stat{Label: "5xx", Source: "stats", Field: "status5xx", Poll: "2s"}},
			),
			w.Widget{Content: w.Table{
				Source: "requests",
				Poll:   "1s",
				Columns: []w.ColumnDef{
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
		),
	}
}

var _ w.AdminProvider = (*Midware)(nil)
