package net

import (
	"errors"
	stdnet "net"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	ngnet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

func init() {
	registerSysInterface()
	registerRouteTable()
}

func registerSysInterface() {
	ng.Register("net::interface::sys",
		ng.Assert{Type: "null", Desc: "use system default interface"},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[ngnet.Interface](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			return &ngnet.SysInterface{}, nil
		},
	)
}

func registerRouteTable() {
	ng.Register("net::routetable::new",
		ng.Assert{
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
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[ngnet.Interface](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			routes := spec.MustGet("routes").ToList()
			table := &ngnet.RouteTable{}

			for _, route := range routes {
				cidr := route.MustGet("cidr").ToString()
				ifaceNode := route.MustGet("interface")
				iface, ok := ifaceNode.Value.(ngnet.Interface)
				if !ok {
					return nil, errors.New("interface ptr is not a net.Interface")
				}
				_, ipnet, err := stdnet.ParseCIDR(cidr)
				if err != nil {
					return nil, err
				}
				table.Routes = append(table.Routes, ngnet.Route{IPNet: *ipnet, Interface: iface})
			}

			return table, nil
		},
	)
}
