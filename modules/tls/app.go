package tls

import (
	"errors"

	"github.com/mrhaoxx/OpenNG/config"
	"github.com/rs/zerolog/log"
)

func init() {
	registerTLS()
	registerReload()
}

func registerTLS() {
	config.Register("tls",
		func(spec *config.ArgNode) (any, error) {
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
		}, config.Assert{
			Type:     "map",
			Required: true,
			Sub: config.AssertMap{
				"certificates": {
					Type: "list",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
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
	config.Register("tls::reload",
		func(spec *config.ArgNode) (any, error) {
			mgr, ok := spec.Value.(*TlsMgr)
			if !ok {
				return nil, errors.New("ptr is not a tls.TlsMgr")
			}
			return nil, mgr.Reload()
		}, config.Assert{
			Type:     "ptr",
			Required: true,
		},
	)
}
