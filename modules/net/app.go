package net

import (
	"errors"
	stdnet "net"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	netpkg "github.com/mrhaoxx/OpenNG/pkg/net"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	ngmodules.Register("net::interface::sys",
		func(spec *ngmodules.ArgNode) (any, error) {
			return &netpkg.SysInterface{}, nil
		}, ngmodules.Assert{Type: "null", Desc: "use system default interface"},
	)
}

func registerRouteTable() {
	ngmodules.Register("net::routetable::new",
		func(spec *ngmodules.ArgNode) (any, error) {
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
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"routes": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
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
