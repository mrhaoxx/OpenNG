package tunnels

import "github.com/mrhaoxx/OpenNG/net"

type Overlay interface {
	Underlying() net.Interface
	Overlying(net.Interface)
}
