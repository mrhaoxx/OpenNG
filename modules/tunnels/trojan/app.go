package trojan

import (
	"crypto/sha256"
	"encoding/hex"

	ng "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	ng.Register("trojan::server",
		func(spec *ng.ArgNode) (any, error) {
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
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"passwords": {
					Type: "list",
					Sub: ng.AssertMap{
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
