package ngtls

import (
	"time"

	ng "github.com/mrhaoxx/OpenNG"
)

func (mgr *TlsMgr) AdminMeta() ng.AdminMeta {
	return ng.AdminMeta{
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
			{Method: "GET", Path: "/certs", Handler: func(ctx ng.AdminContext) {
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
				ng.WriteJSON(ctx.ResponseWriter(), 200, result)
			}},
		},
		Root: ng.Columns(
			ng.Column(12,
				ng.Card("Certificates",
					ng.Widget{Content: ng.Table{
						Source: "certs",
						Columns: []ng.ColumnDef{
							{Field: "certfile", Label: "File", Type: "string"},
							{Field: "domains", Label: "Domains", Type: "string"},
							{Field: "issuer", Label: "Issuer", Type: "string"},
							{Field: "notAfter", Label: "Expires", Type: "datetime"},
						},
					}},
				),
				ng.Widget{Content: ng.Action{
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

var _ ng.AdminProvider = (*TlsMgr)(nil)
