package trojan

import (
	"crypto/sha256"
	"encoding/hex"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	opennet "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	ngmodules.Register("trojan::server",
		func(spec *ngmodules.ArgNode) (any, error) {
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
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"passwords": {
					Type: "list",
					Sub: ngmodules.AssertMap{
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
