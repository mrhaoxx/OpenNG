package tcp

import (
	"net"
)

type ipfilter struct {
	allowedCIDR map[string]*net.IPNet
}

func (filter *ipfilter) Handle(c *Conn) SerRet {
	// Check if the IP is allowed
	host, _, err := net.SplitHostPort(c.Addr().String())
	if err != nil {
		panic(err)
	}
	for _, v := range filter.allowedCIDR {
		if v.Contains(net.ParseIP(host)) {
			return Continue
		}
	}
	return Close
}

func NewIPFilter(allowedCIDR []string) *ipfilter {
	filter := &ipfilter{
		allowedCIDR: make(map[string]*net.IPNet),
	}
	for _, v := range allowedCIDR {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			panic(err)
		}
		filter.allowedCIDR[v] = ipnet
	}
	return filter
}
