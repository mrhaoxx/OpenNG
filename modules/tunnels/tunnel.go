package tunnels

import "github.com/mrhaoxx/OpenNG/pkg/net"

type Overlay interface {
	Underlying() net.Interface
	Overlying(net.Interface)
}
