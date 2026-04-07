package wireguard

import (
	"time"

	ng "github.com/mrhaoxx/OpenNG"
	ngnet "github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

func init() {
	ng.RegisterFunc("wireguard::server", NewWireGuardServerFromConfig)
}

// --- wireguard::server ---

type WireGuardPeerConfig struct {
	PublicKey  string   `ng:"PublicKey,required"`
	AllowedIPs []string `ng:"AllowedIPs"`
}

type WireGuardTCPConfig struct {
	CatchTimeout      time.Duration `ng:"CatchTimeout" type:"duration" default:"600ms"`
	ConnTimeout       time.Duration `ng:"ConnTimeout" type:"duration" default:"3s"`
	KeepaliveIdle     time.Duration `ng:"KeepaliveIdle" type:"duration" default:"45s"`
	KeepaliveInterval time.Duration `ng:"KeepaliveInterval" type:"duration" default:"45s"`
	KeepaliveCount    int           `ng:"KeepaliveCount" default:"3"`
}

type WireGuardForwardingConfig struct {
	EnableTCP bool               `ng:"EnableTCP" default:"true"`
	EnableUDP bool               `ng:"EnableUDP" default:"true"`
	TCP       WireGuardTCPConfig `ng:"TCP"`
}

type WireGuardServerConfig struct {
	ListenPort int                       `ng:"ListenPort,required"`
	PrivateKey string                    `ng:"PrivateKey,required"`
	Address    string                    `ng:"Address,required"`
	MTU        int                       `ng:"MTU" default:"1420"`
	Peers      []WireGuardPeerConfig     `ng:"Peers"`
	Forwarding WireGuardForwardingConfig `ng:"Forwarding"`
}

func NewWireGuardServerFromConfig(cfg WireGuardServerConfig) (ngnet.Interface, error) {
	var peers []PeerConfig
	for _, p := range cfg.Peers {
		peers = append(peers, PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AllowedIPs,
		})
	}

	wgCfg := &WireGuardConfig{
		ListenPort:           cfg.ListenPort,
		PrivateKey:           cfg.PrivateKey,
		Address:              cfg.Address,
		MTU:                  cfg.MTU,
		EnableTCP:            cfg.Forwarding.EnableTCP,
		EnableUDP:            cfg.Forwarding.EnableUDP,
		TcpCatchTimeout:      cfg.Forwarding.TCP.CatchTimeout,
		TcpConnTimeout:       cfg.Forwarding.TCP.ConnTimeout,
		TcpKeepaliveIdle:     cfg.Forwarding.TCP.KeepaliveIdle,
		TcpKeepaliveInterval: cfg.Forwarding.TCP.KeepaliveInterval,
		TcpKeepAliveCount:    cfg.Forwarding.TCP.KeepaliveCount,
		Peers:                peers,
	}

	return NewWireGuardServer(wgCfg)
}
