package ngtcp

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func (ctl *Controller) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Title:    "TCP Controller",
		Category: "Network",
		Routes: []ng.AdminRoute{
			{Method: "GET", Path: "/connections", Handler: func(ctx ng.AdminContext) {
				res, _ := ctl.Report()
				ng.WriteJSON(ctx.ResponseWriter(), 200, res)
			}},
		},
	}
}

var _ ng.AdminProvider = (*Controller)(nil)
