package wireguard

import (
	"time"

	ng "github.com/mrhaoxx/OpenNG"
)

func init() {
	registerServer()
	registerAddPeers()
}

func registerServer() {
	ng.Register("wireguard::server",
		func(spec *ng.ArgNode) (any, error) {
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
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"ListenPort": {Type: "int", Required: true},
				"PrivateKey": {Type: "string", Required: true},
				"Address":    {Type: "string", Required: true},
				"MTU":        {Type: "int", Default: 1420},
				"Forwarding": {
					Type:    "map",
					Default: map[string]*ng.ArgNode{},
					Sub: ng.AssertMap{
						"EnableTCP": {Type: "bool", Default: true},
						"EnableUDP": {Type: "bool", Default: true},
						"TCP": {
							Type:    "map",
							Default: map[string]*ng.ArgNode{},
							Sub: ng.AssertMap{
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
	ng.Register("wireguard::addpeers",
		func(spec *ng.ArgNode) (any, error) {
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
		}, ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Peers": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"PublicKey": {Type: "string", Required: true},
								"AllowedIPs": {
									Type: "list",
									Sub: ng.AssertMap{
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
