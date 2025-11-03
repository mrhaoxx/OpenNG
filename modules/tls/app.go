package tls

import (
	"errors"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/rs/zerolog/log"
)

func init() {
	registerTLS()
	registerReload()
}

func registerTLS() {
	ng.Register("tls",
		ng.Assert{
			Type:     "map",
			Required: true,
			Sub: ng.AssertMap{
				"certificates": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"CertFile": {
									Type:     "string",
									Required: true,
									Desc:     "path to certificate file",
								},
								"KeyFile": {
									Type:     "string",
									Required: true,
									Desc:     "path to key file",
								},
							},
						},
					},
				},
			},
		},
		ng.Assert{Type: "ptr"},
		func(spec *ng.ArgNode) (any, error) {
			certs := spec.MustGet("certificates").ToList()

			mgr := NewTlsMgr()

			for _, cert := range certs {
				certfile := cert.MustGet("CertFile").ToString()
				keyfile := cert.MustGet("KeyFile").ToString()

				if err := mgr.LoadCertificate(certfile, keyfile); err != nil {
					return nil, err
				}

				log.Debug().
					Str("certfile", certfile).
					Str("keyfile", keyfile).
					Msg("new tls certificate")
			}

			return mgr, nil
		},
	)
}

func registerReload() {
	ng.Register("tls::reload",
		ng.Assert{
			Type:     "ptr",
			Required: true,
		},
		ng.Assert{Type: "null"},
		func(spec *ng.ArgNode) (any, error) {
			mgr, ok := spec.Value.(*TlsMgr)
			if !ok {
				return nil, errors.New("ptr is not a tls.TlsMgr")
			}
			return nil, mgr.Reload()
		},
	)
}
