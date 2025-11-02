package netgate

import (
	"errors"
	stdnet "net"

	netpkg "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	Register("net::interface::sys",
		func(spec *ArgNode) (any, error) {
			return &netpkg.SysInterface{}, nil
		}, Assert{Type: "null", Desc: "use system default interface"},
	)
}

func registerRouteTable() {
	Register("net::routetable::new",
		func(spec *ArgNode) (any, error) {
			routes := spec.MustGet("routes").ToList()
			table := &netpkg.RouteTable{}

			for _, route := range routes {
				cidr := route.MustGet("cidr").ToString()
				ifaceNode := route.MustGet("interface")
				iface, ok := ifaceNode.Value.(netpkg.Interface)
				if !ok {
					return nil, errors.New("interface ptr is not a net.Interface")
				}
				_, ipnet, err := stdnet.ParseCIDR(cidr)
				if err != nil {
					return nil, err
				}
				table.Routes = append(table.Routes, netpkg.Route{IPNet: *ipnet, Interface: iface})
			}

			return table, nil
		}, Assert{
			Type: "map",
			Sub: AssertMap{
				"routes": {
					Type: "list",
					Sub: AssertMap{
						"_": {
							Type: "map",
							Sub: AssertMap{
								"cidr":      {Type: "string", Required: true},
								"interface": {Type: "ptr", Required: true},
							},
						},
					},
				},
			},
		},
	)
}
