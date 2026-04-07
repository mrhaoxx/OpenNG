package tunnels

import "github.com/mrhaoxx/OpenNG/modules/ngnet"

type Overlay interface {
	Underlying() ngnet.Interface
	Overlying(ngnet.Interface)
}
