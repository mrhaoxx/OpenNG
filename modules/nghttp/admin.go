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
			{Method: "GET", Path: "/stats", Handler: func(ctx ng.AdminContext) {
				ng.WriteJSON(ctx.ResponseWriter(), 200, map[string]any{
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
		Root: ng.Column(1,
			ng.Row(
				ng.Widget{Content: ng.Stat{Label: "Total Requests", Source: "stats", Field: "totalRequests", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "Active", Source: "stats", Field: "activeRequests", Poll: "1s"}},
				ng.Widget{Content: ng.Stat{Label: "Req/s (5s)", Source: "stats", Field: "reqRate5s", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "Total TX", Source: "stats", Field: "totalBytesOut", Unit: "bytes", Poll: "2s"}},
			),
			ng.Row(
				ng.Widget{Content: ng.Stat{Label: "2xx", Source: "stats", Field: "status2xx", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "3xx", Source: "stats", Field: "status3xx", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "4xx", Source: "stats", Field: "status4xx", Poll: "2s"}},
				ng.Widget{Content: ng.Stat{Label: "5xx", Source: "stats", Field: "status5xx", Poll: "2s"}},
			),
			ng.Widget{Content: ng.Table{
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
		),
	}
}

var _ ng.AdminProvider = (*Midware)(nil)
