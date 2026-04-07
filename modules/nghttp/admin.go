package nghttp

import (
	"encoding/json"
	stdhttp "net/http"

	ng "github.com/mrhaoxx/OpenNG"
)

func (mid *Midware) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Name:     "http",
		Title:    "HTTP Requests",
		Category: "network",
		Routes: []ng.AdminRoute{
			{
				Method: stdhttp.MethodGet,
				Path:   "/api/v1/http/requests",
				Desc:   "List active HTTP requests",
				Handler: func(ctx ng.AdminContext) {
					w := ctx.ResponseWriter()
					res, err := mid.Report()
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

var _ ng.AdminProvider = (*Midware)(nil)
