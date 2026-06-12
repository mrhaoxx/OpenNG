//go:build unix

package ngnet

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReusePortListenConfig returns a net.ListenConfig with SO_REUSEPORT set, so
// consecutive service generations can bind the same address simultaneously
// and hand traffic over without a close/rebind gap. Used for UDP, where no
// accept boundary exists for the listener registry to dispatch on.
func ReusePortListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
}
