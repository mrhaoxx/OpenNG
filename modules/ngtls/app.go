package ngtls

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/rs/zerolog/log"
)

func init() {
	ng.RegisterFunc("tls", NewTlsMgrFromConfig)
}

type CertConfig struct {
	CertFile string `ng:"CertFile,required" desc:"path to certificate file"`
	KeyFile  string `ng:"KeyFile,required" desc:"path to key file"`
}

type TlsConfig struct {
	Certificates []CertConfig `ng:"certificates"`
	ClientCAs    []string     `ng:"ClientCAs" desc:"list of client CA certificate files for mTLS"`
}

func NewTlsMgrFromConfig(cfg TlsConfig) (*TlsMgr, error) {
	mgr := NewTlsMgr()

	for _, cert := range cfg.Certificates {
		if err := mgr.LoadCertificate(cert.CertFile, cert.KeyFile); err != nil {
			return nil, err
		}

		log.Debug().
			Str("certfile", cert.CertFile).
			Str("keyfile", cert.KeyFile).
			Msg("new tls certificate")
	}

	for _, cafile := range cfg.ClientCAs {
		if err := mgr.LoadClientCA(cafile); err != nil {
			return nil, err
		}
		log.Debug().
			Str("cafile", cafile).
			Msg("loaded client CA")
	}

	return mgr, nil
}
