package wireguard

import (
	"time"

	ngmodules "github.com/mrhaoxx/OpenNG/modules"
)

func init() {
	registerServer()
	registerAddPeers()
}

func registerServer() {
	ngmodules.Register("wireguard::server",
		func(spec *ngmodules.ArgNode) (any, error) {
			listenPort := spec.MustGet("ListenPort").ToInt()
			privateKey := spec.MustGet("PrivateKey").ToString()
			address := spec.MustGet("Address").ToString()
			mtu := spec.MustGet("MTU").ToInt()

			forwarding := spec.MustGet("Forwarding")
			enableTCP := forwarding.MustGet("EnableTCP").ToBool()
			enableUDP := forwarding.MustGet("EnableUDP").ToBool()
			tcpNode := forwarding.MustGet("TCP")
			catchTimeout := tcpNode.MustGet("CatchTimeout").ToDuration()
			connTimeout := tcpNode.MustGet("ConnTimeout").ToDuration()
			keepaliveIdle := tcpNode.MustGet("KeepaliveIdle").ToDuration()
			keepaliveInterval := tcpNode.MustGet("KeepaliveInterval").ToDuration()
			keepaliveCount := tcpNode.MustGet("KeepaliveCount").ToInt()

			cfg := &WireGuardConfig{
				ListenPort:           listenPort,
				PrivateKey:           privateKey,
				Address:              address,
				MTU:                  mtu,
				EnableTCP:            enableTCP,
				EnableUDP:            enableUDP,
				TcpCatchTimeout:      catchTimeout,
				TcpConnTimeout:       connTimeout,
				TcpKeepaliveIdle:     keepaliveIdle,
				TcpKeepaliveInterval: keepaliveInterval,
				TcpKeepAliveCount:    keepaliveCount,
			}

			return NewWireGuardServer(cfg)
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"ListenPort": {Type: "int", Required: true},
				"PrivateKey": {Type: "string", Required: true},
				"Address":    {Type: "string", Required: true},
				"MTU":        {Type: "int", Default: 1420},
				"Forwarding": {
					Type:    "map",
					Default: map[string]*ngmodules.ArgNode{},
					Sub: ngmodules.AssertMap{
						"EnableTCP": {Type: "bool", Default: true},
						"EnableUDP": {Type: "bool", Default: true},
						"TCP": {
							Type:    "map",
							Default: map[string]*ngmodules.ArgNode{},
							Sub: ngmodules.AssertMap{
								"CatchTimeout": {
									Type:    "duration",
									Default: time.Duration(600 * time.Millisecond),
								},
								"ConnTimeout": {
									Type:    "duration",
									Default: time.Duration(3 * time.Second),
								},
								"KeepaliveIdle": {
									Type:    "duration",
									Default: time.Duration(45 * time.Second),
								},
								"KeepaliveInterval": {
									Type:    "duration",
									Default: time.Duration(45 * time.Second),
								},
								"KeepaliveCount": {
									Type:    "int",
									Default: 3,
								},
							},
						},
					},
				},
			},
		},
	)
}

func registerAddPeers() {
	ngmodules.Register("wireguard::addpeers",
		func(spec *ngmodules.ArgNode) (any, error) {
			peers := spec.MustGet("Peers").ToList()
			server := spec.MustGet("server").Value.(*WireGuardServer)

			for _, peer := range peers {
				publicKey := peer.MustGet("PublicKey").ToString()
				allowedIPs := peer.MustGet("AllowedIPs").ToStringList()

				if err := server.AddPeer(publicKey, allowedIPs); err != nil {
					return nil, err
				}
			}

			return nil, nil
		}, ngmodules.Assert{
			Type: "map",
			Sub: ngmodules.AssertMap{
				"Peers": {
					Type: "list",
					Sub: ngmodules.AssertMap{
						"_": {
							Type: "map",
							Sub: ngmodules.AssertMap{
								"PublicKey": {Type: "string", Required: true},
								"AllowedIPs": {
									Type: "list",
									Sub: ngmodules.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
				"server": {Type: "ptr", Required: true},
			},
		},
	)
}
