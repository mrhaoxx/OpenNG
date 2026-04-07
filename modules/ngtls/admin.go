package ngtls

import (
	stdhttp "net/http"

	ng "github.com/mrhaoxx/OpenNG"
)

func (mgr *TlsMgr) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Name:     "tls",
		Title:    "TLS Manager",
		Category: "security",
		Routes: []ng.AdminRoute{
			{
				Method: stdhttp.MethodPost,
				Path:   "/api/v1/tls/reload",
				Desc:   "Reload TLS certificates",
				Handler: func(ctx ng.AdminContext) {
					w := ctx.ResponseWriter()
					w.Header().Set("Cache-Control", "no-cache")
					if err := mgr.Reload(); err != nil {
						w.WriteHeader(stdhttp.StatusBadRequest)
						w.Write([]byte(err.Error()))
					} else {
						w.WriteHeader(stdhttp.StatusAccepted)
					}
				},
			},
		},
	}
}

var _ ng.AdminProvider = (*TlsMgr)(nil)
