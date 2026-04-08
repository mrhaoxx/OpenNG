package ngtls

import (
	"time"

	"github.com/mrhaoxx/OpenNG/modules/admin/admeta"
)

func (mgr *TlsMgr) Meta() admeta.Meta {
	return admeta.Meta{
		Routes: []admeta.Route{
			{Method: "POST", Path: "/reload", Handler: func(ctx admeta.Context) {
				rw := ctx.ResponseWriter()
				if err := mgr.Reload(); err != nil {
					rw.WriteHeader(400)
					rw.Write([]byte(err.Error()))
				} else {
					rw.WriteHeader(202)
				}
			}},
			{Method: "GET", Path: "/certs", Handler: func(ctx admeta.Context) {
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
				admeta.WriteJSON(ctx.ResponseWriter(), 200, result)
			}},
		},
		Root: admeta.Columns(
			admeta.Column(12,
				admeta.Card("Certificates",
					admeta.Widget{Content: admeta.Table{
						Source: "certs",
						Columns: []admeta.ColumnDef{
							{Field: "certfile", Label: "File", Type: "string"},
							{Field: "domains", Label: "Domains", Type: "string"},
							{Field: "issuer", Label: "Issuer", Type: "string"},
							{Field: "notAfter", Label: "Expires", Type: "datetime"},
						},
					}},
				),
				admeta.Widget{Content: admeta.Action{
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

var _ admeta.Provider = (*TlsMgr)(nil)
