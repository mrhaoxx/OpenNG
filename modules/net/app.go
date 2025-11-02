package net

import (
	"errors"
	stdnet "net"

	"github.com/mrhaoxx/OpenNG/config"
	netpkg "github.com/mrhaoxx/OpenNG/net"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	config.Register("net::interface::sys",
		func(spec *config.ArgNode) (any, error) {
			return &netpkg.SysInterface{}, nil
		}, config.Assert{Type: "null", Desc: "use system default interface"},
	)
}

func registerRouteTable() {
	config.Register("net::routetable::new",
		func(spec *config.ArgNode) (any, error) {
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
		}, config.Assert{
			Type: "map",
			Sub: config.AssertMap{
				"routes": {
					Type: "list",
					Sub: config.AssertMap{
						"_": {
							Type: "map",
							Sub: config.AssertMap{
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
