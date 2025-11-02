package trojan

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/mrhaoxx/OpenNG/config"
	opennet "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	config.Register("trojan::server",
		func(spec *config.ArgNode) (any, error) {
			passwords := spec.MustGet("passwords").ToStringList()
			iface := spec.MustGet("interface")

			var underlying opennet.Interface
			if iface != nil {
				underlying = iface.Value.(opennet.Interface)
			}

			for i, password := range passwords {
				sum := sha256.Sum224([]byte(password))
				passwords[i] = hex.EncodeToString(sum[:])
			}

			return &Server{
				PasswordHashes: passwords,
				Underlying:     underlying,
			}, nil
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"passwords": {
					Type: "list",
					Sub: config.AssertMap{
						"_": {Type: "string"},
					},
				},
				"interface": {
					Type:    "ptr",
					Default: "sys",
				},
			},
		},
	)
}
