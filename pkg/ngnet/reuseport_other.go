//go:build !unix

package ngnet

import "net"

// ReusePortListenConfig: SO_REUSEPORT is unavailable on this platform.
// Binds behave like a plain net.ListenConfig — a new generation's bind
// fails while the previous one still holds the address, so reloads that
// change UDP bindings require the old generation to stop first.
func ReusePortListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
