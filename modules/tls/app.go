package tls

import (
	"errors"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	"github.com/rs/zerolog/log"
)

func init() {
	registerTLS()
	registerReload()
}

func registerTLS() {
	ngmodules.Register("tls",
		func(spec *ngmodules.ArgNode) (any, error) {
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
		}, ngmodules.Assert{
			Type:     "map",
			Required: true,
			Sub: ngmodules.AssertMap{
				"certificates": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
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
	)
}

func registerReload() {
	ngmodules.Register("tls::reload",
		func(spec *ngmodules.ArgNode) (any, error) {
			mgr, ok := spec.Value.(*TlsMgr)
			if !ok {
				return nil, errors.New("ptr is not a tls.TlsMgr")
			}
			return nil, mgr.Reload()
		}, ngmodules.Assert{
			Type:     "ptr",
			Required: true,
		},
	)
}
