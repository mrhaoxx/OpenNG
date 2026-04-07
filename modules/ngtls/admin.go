package ngtls

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func (mgr *TlsMgr) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
		Title:    "TLS Manager",
		Category: "Security",
		Routes: []ng.AdminRoute{
			{Method: "POST", Path: "/reload", Handler: func(ctx ng.AdminContext) {
				w := ctx.ResponseWriter()
				if err := mgr.Reload(); err != nil {
					w.WriteHeader(400)
					w.Write([]byte(err.Error()))
				} else {
					w.WriteHeader(202)
				}
			}},
		},
	}
}

var _ ng.AdminProvider = (*TlsMgr)(nil)
