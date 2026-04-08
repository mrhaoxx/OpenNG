package ngtls

import (
	"time"

	w "github.com/mrhaoxx/OpenNG/modules/admin/widget"
)

func (mgr *TlsMgr) AdminMeta() w.AdminMeta {
	return w.AdminMeta{
		Routes: []w.AdminRoute{
			{Method: "POST", Path: "/reload", Handler: func(ctx w.AdminContext) {
				rw := ctx.ResponseWriter()
				if err := mgr.Reload(); err != nil {
					rw.WriteHeader(400)
					rw.Write([]byte(err.Error()))
				} else {
					rw.WriteHeader(202)
				}
			}},
			{Method: "GET", Path: "/certs", Handler: func(ctx w.AdminContext) {
				certs := mgr.GetActiveCertificates()
				type certInfo struct {
					CertFile  string   `json:"certfile"`
					Domains   []string `json:"domains"`
					NotBefore string   `json:"notBefore"`
					NotAfter  string   `json:"notAfter"`
					Issuer    string   `json:"issuer"`
				}
				var result []certInfo
				for _, c := range certs {
					if c.Leaf == nil {
						continue
					}
					result = append(result, certInfo{
						CertFile:  c.certfile,
						Domains:   certNames(c.Leaf),
						NotBefore: c.Leaf.NotBefore.Format(time.RFC3339),
						NotAfter:  c.Leaf.NotAfter.Format(time.RFC3339),
						Issuer:    c.Leaf.Issuer.CommonName,
					})
				}
				w.WriteJSON(ctx.ResponseWriter(), 200, result)
			}},
		},
		Root: w.Columns(
			w.Column(12,
				w.Card("Certificates",
					w.Widget{Content: w.Table{
						Source: "certs",
						Columns: []w.ColumnDef{
							{Field: "certfile", Label: "File", Type: "string"},
							{Field: "domains", Label: "Domains", Type: "string"},
							{Field: "issuer", Label: "Issuer", Type: "string"},
							{Field: "notAfter", Label: "Expires", Type: "datetime"},
						},
					}},
				),
				w.Widget{Content: w.Action{
					Label:    "Reload Certificates",
					Endpoint: "reload",
					Method:   "POST",
					Variant:  "default",
					Confirm:  "Reload all TLS certificates?",
				}},
			),
		),
	}
}

var _ w.AdminProvider = (*TlsMgr)(nil)
