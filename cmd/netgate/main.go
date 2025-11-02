package main

import (
	ngcmd "github.com/mrhaoxx/OpenNG/cmd"
	_ "github.com/mrhaoxx/OpenNG/modules/admin"
	_ "github.com/mrhaoxx/OpenNG/modules/auth"
	_ "github.com/mrhaoxx/OpenNG/modules/dns"
	_ "github.com/mrhaoxx/OpenNG/modules/expr"
	_ "github.com/mrhaoxx/OpenNG/modules/http"
	_ "github.com/mrhaoxx/OpenNG/modules/log"
	_ "github.com/mrhaoxx/OpenNG/modules/misc"
	_ "github.com/mrhaoxx/OpenNG/modules/net"
	_ "github.com/mrhaoxx/OpenNG/modules/ssh"
	_ "github.com/mrhaoxx/OpenNG/modules/tcp"
	_ "github.com/mrhaoxx/OpenNG/modules/tls"

	_ "github.com/mrhaoxx/OpenNG/modules/tunnels/http"
	_ "github.com/mrhaoxx/OpenNG/modules/tunnels/trojan"
	_ "github.com/mrhaoxx/OpenNG/modules/tunnels/wireguard"
)

func main() {
	ngcmd.Main()
}
