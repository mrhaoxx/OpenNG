package net

import (
	"errors"
	stdnet "net"

	ng "github.com/mrhaoxx/OpenNG"
	netpkg "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	ng.Register("net::interface::sys",
		func(spec *ng.ArgNode) (any, error) {
			return &netpkg.SysInterface{}, nil
		}, ng.Assert{Type: "null", Desc: "use system default interface"},
	)
}

func registerRouteTable() {
	ng.Register("net::routetable::new",
		func(spec *ng.ArgNode) (any, error) {
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
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"routes": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
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
