package nghttp

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func (mid *Midware) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Title:    "HTTP Midware",
		Category: "Network",
		Routes: []ng.AdminRoute{
			{Method: "GET", Path: "/requests", Handler: func(ctx ng.AdminContext) {
				res, _ := mid.Report()
				ng.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
		},
	}
}

var _ ng.AdminProvider = (*Midware)(nil)
