package ngnet

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
	ListenPacket(network, address string) (net.PacketConn, error)
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

// Listen binds with SO_REUSEPORT so consecutive service generations can hold
// the same address at once and hand connections over without a rebind gap;
// when a generation closes its listener the kernel routes to whoever is left.
func (s *SysInterface) Listen(network, address string) (net.Listener, error) {
	lc := ReusePortListenConfig()
	return lc.Listen(context.Background(), network, address)
}

// ListenPacket binds a UDP socket with SO_REUSEPORT, the datagram counterpart
// of Listen's generation handoff.
func (s *SysInterface) ListenPacket(network, address string) (net.PacketConn, error) {
	lc := ReusePortListenConfig()
	return lc.ListenPacket(context.Background(), network, address)
}

var _ Interface = (*SysInterface)(nil)
