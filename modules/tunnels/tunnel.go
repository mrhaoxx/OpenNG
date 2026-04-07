package tunnels

import "github.com/mrhaoxx/OpenNG/pkg/ngnet"

type Overlay interface {
	Underlying() ngnet.Interface
	Overlying(ngnet.Interface)
}
