//go:build !unix

package ngnet

import "net"

// SupportsListenerHandoff reports whether two service generations can bind the
// same address at once (SO_REUSEPORT) and hand connections over without a gap.
// False here: callers must stop the old generation before binding the new one.
const SupportsListenerHandoff = false

// ReusePortListenConfig: SO_REUSEPORT is unavailable on this platform.
// Binds behave like a plain net.ListenConfig — a new generation's bind
// fails while the previous one still holds the address, so reloads that
// change a binding require the old generation to stop first
// (see SupportsListenerHandoff and the reload flow in cmd).
func ReusePortListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
