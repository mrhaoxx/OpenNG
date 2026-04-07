package ngtcp

import (
	"encoding/json"
	stdhttp "net/http"

	ng "github.com/mrhaoxx/OpenNG"
)

func (ctl *Controller) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Name:     "tcp",
		Title:    "TCP Connections",
		Category: "network",
		Routes: []ng.AdminRoute{
			{
				Method: stdhttp.MethodGet,
				Path:   "/api/v1/tcp/connections",
				Desc:   "List active TCP connections",
				Handler: func(ctx ng.AdminContext) {
					w := ctx.ResponseWriter()
					res, err := ctl.Report()
					if err != nil {
						ng.WriteJSON(w, stdhttp.StatusInternalServerError, map[string]string{"error": err.Error()})
						return
					}
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.Header().Set("Cache-Control", "no-cache")
					byt, err := json.Marshal(res)
					if err != nil {
						ng.WriteJSON(w, stdhttp.StatusInternalServerError, map[string]string{"error": err.Error()})
						return
					}
					w.WriteHeader(stdhttp.StatusOK)
					w.Write(byt)
				},
			},
		},
	}
}

var _ ng.AdminProvider = (*Controller)(nil)
