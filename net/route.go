package net

import (
	"context"
	"errors"
	"net"
	"strings"
)

type Route struct {
	net.IPNet
	Interface
}

type RouteTable struct {
	Routes []Route
}

func (rt *RouteTable) findInterfaceForIP(ip net.IP) Interface {
	if rt == nil || ip == nil {
		return nil
	}
	for _, route := range rt.Routes {
		if route.Contains(ip) {
			return route
		}
	}
	return nil
}

func resolveHostToIP(host string) net.IP {
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return ips[0]
}

func (rt *RouteTable) Dial(network, address string) (net.Conn, error) {
	return rt.DialContext(context.Background(), network, address)
}

func (rt *RouteTable) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip := resolveHostToIP(host)
	if ip != nil {
		ifc := rt.findInterfaceForIP(ip)
		if ifc != nil {
			return ifc.DialContext(ctx, network, address)
		}
	}
	return nil, errors.New("no interface found")
}

func (rt *RouteTable) Listen(network, address string) (net.Listener, error) {
	if strings.HasPrefix(network, "unix") {
		return nil, errors.New("no interface found")
	}
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip := resolveHostToIP(host)
	if ip != nil && !ip.IsUnspecified() {
		ifc := rt.findInterfaceForIP(ip)
		if ifc != nil {
			return ifc.Listen(network, address)
		}
	}
	return nil, errors.New("no interface found")
}

var DefaultRouteTable = &RouteTable{
	Routes: []Route{
		{
			IPNet: net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 0),
			},
			Interface: &SysInterface{},
		},
	},
}
