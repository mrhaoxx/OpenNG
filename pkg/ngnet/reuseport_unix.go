//go:build unix

package ngnet

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// SupportsListenerHandoff reports whether two service generations can bind the
// same address at once (SO_REUSEPORT) and hand connections over without a gap.
// True here: a reload co-binds the new generation, then stops the old one.
const SupportsListenerHandoff = true

// ReusePortListenConfig returns a net.ListenConfig with SO_REUSEPORT set, so
// consecutive service generations can bind the same address simultaneously
// and hand traffic over without a close/rebind gap. Used by SysInterface for
// both TCP and UDP.
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
