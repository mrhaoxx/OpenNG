package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	opennet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

func init() {
	ng.Register("trojan::server",
		ng.Assert{
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
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.Iface[tcp.Service](),
			},
		},
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
		},
	)
}
