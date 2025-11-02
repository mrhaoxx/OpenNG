package trojan

import (
	"crypto/sha256"
	"encoding/hex"

	netgate "github.com/mrhaoxx/OpenNG"
	opennet "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	netgate.Register("trojan::server",
		func(spec *netgate.ArgNode) (any, error) {
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
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"passwords": {
					Type: "list",
					Sub: netgate.AssertMap{
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
