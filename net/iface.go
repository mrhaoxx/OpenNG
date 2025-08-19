package net

import (
	"context"
	"errors"
	"net"
)

var (
	ErrNoInterface      = errors.New("no interface found")
	ErrTCPOnly          = errors.New("only tcp is supported")
	ErrUDPOnly          = errors.New("only udp is supported")
	ErrDialNotSupport   = errors.New("dialing not supported")
	ErrListenNotSupport = errors.New("listening not supported")
)

type Interface interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Listen(network, address string) (net.Listener, error)
}

type Listener interface {
	net.Listener
}

type SysInterface struct{}

func (s *SysInterface) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (s *SysInterface) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (s *SysInterface) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
