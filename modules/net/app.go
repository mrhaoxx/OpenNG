package net

import (
	"errors"
	stdnet "net"

	netgate "github.com/mrhaoxx/OpenNG"
	netpkg "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	netgate.Register("net::interface::sys",
		func(spec *netgate.ArgNode) (any, error) {
			return &netpkg.SysInterface{}, nil
		}, netgate.Assert{Type: "null", Desc: "use system default interface"},
	)
}

func registerRouteTable() {
	netgate.Register("net::routetable::new",
		func(spec *netgate.ArgNode) (any, error) {
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
		}, netgate.Assert{
			Type: "map",
			Sub: netgate.AssertMap{
				"routes": {
					Type: "list",
					Sub: netgate.AssertMap{
						"_": {
							Type: "map",
							Sub: netgate.AssertMap{
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
