package ngtls

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/rs/zerolog/log"
)

func init() {
	registerTLS()
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
				"ClientCAs": {
					Type: "list",
					Desc: "list of client CA certificate files for mTLS",
					Sub: ng.AssertMap{
						"_": {Type: "string", Desc: "path to client CA certificate file"},
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

			clientCAs := spec.MustGet("ClientCAs").ToStringList()
			for _, cafile := range clientCAs {
				if err := mgr.LoadClientCA(cafile); err != nil {
					return nil, err
				}
				log.Debug().
					Str("cafile", cafile).
					Msg("loaded client CA")
			}

			return mgr, nil
		},
	)
}
