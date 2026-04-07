package net

import (
	stdnet "net"
	"errors"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

func init() {
	ng.RegisterFunc("net::interface::sys", func(struct{}) (ngnet.Interface, error) {
		return &ngnet.SysInterface{}, nil
	})

	ng.RegisterFunc("net::routetable::new", NewRouteTable)
}

type RouteConfig struct {
	CIDR      string         `ng:"cidr,required" desc:"CIDR notation (e.g. 192.168.1.0/24)"`
	Interface ngnet.Interface `ng:"interface,required"`
}

type RouteTableConfig struct {
	Routes []RouteConfig `ng:"routes"`
}

func NewRouteTable(cfg RouteTableConfig) (*ngnet.RouteTable, error) {
	table := &ngnet.RouteTable{}
	for _, route := range cfg.Routes {
		_, ipnet, err := stdnet.ParseCIDR(route.CIDR)
		if err != nil {
			return nil, err
		}
		if route.Interface == nil {
			return nil, errors.New("interface ptr is not a net.Interface")
		}
		table.Routes = append(table.Routes, ngnet.Route{IPNet: *ipnet, Interface: route.Interface})
	}
	return table, nil
}
