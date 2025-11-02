package tls

import (
	"errors"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/rs/zerolog/log"
)

func init() {
	registerTLS()
	registerReload()
}

func registerTLS() {
	netgate.Register("tls",
		func(spec *netgate.ArgNode) (any, error) {
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
		}, netgate.Assert{
			Type:     "map",
			Required: true,
			Sub: netgate.AssertMap{
				"certificates": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {
							Type: "map",
							Sub: netgate.AssertMap{
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
	netgate.Register("tls::reload",
		func(spec *netgate.ArgNode) (any, error) {
			mgr, ok := spec.Value.(*TlsMgr)
			if !ok {
				return nil, errors.New("ptr is not a tls.TlsMgr")
			}
			return nil, mgr.Reload()
		}, netgate.Assert{
			Type:     "ptr",
			Required: true,
		},
	)
}
