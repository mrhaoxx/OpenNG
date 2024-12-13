package wireguard

import (
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/wireguard/netstack"
	"github.com/mrhaoxx/OpenNG/wireguard/tcp"
	"github.com/mrhaoxx/OpenNG/wireguard/udp"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type WireGuardServer struct {
	tun      tun.Device
	tnet     *netstack.Net
	wgDevice *device.Device
}

type WireGuardConfig struct {
	ListenPort int
	PrivateKey string
	Address    string
	MTU        int

	EnableTCP bool
	EnableUDP bool

	TcpCatchTimeout      time.Duration
	TcpConnTimeout       time.Duration
	TcpKeepaliveIdle     time.Duration
	TcpKeepaliveInterval time.Duration
	TcpKeepAliveCount    int
}

func NewWireGuardServer(cfg *WireGuardConfig) (*WireGuardServer, error) {

	addr, err := netip.ParseAddr(cfg.Address)

	if err != nil {
		return nil, err
	}

	privatekey, err := b64tohex(cfg.PrivateKey)

	if err != nil {
		return nil, err
	}

	tunDevice, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{addr},
		[]netip.Addr{},
		cfg.MTU,
	)

	if err != nil {
		return nil, err
	}

	tnet.Stack().SetPromiscuousMode(1, true)

	logger := device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Verbosef("[wireguard] "+format, args...)
		},
		Errorf: log.Errorf,
	}

	bind := conn.NewDefaultBind()

	wgDevice := device.NewDevice(tunDevice, bind, &logger)

	err = wgDevice.IpcSet("private_key=" + privatekey + "\nlisten_port=" + strconv.Itoa(cfg.ListenPort))

	if err != nil {
		wgDevice.Close()
		return nil, err
	}

	lock := sync.Mutex{}
	s := tnet.Stack()

	if cfg.EnableTCP {
		tcpConfig := tcp.Config{
			CatchTimeout:      cfg.TcpCatchTimeout,
			ConnTimeout:       cfg.TcpConnTimeout,
			KeepaliveIdle:     cfg.TcpKeepaliveIdle,
			KeepaliveInterval: cfg.TcpKeepaliveInterval,
			KeepaliveCount:    cfg.TcpKeepAliveCount,
			Tnet:              tnet,
			StackLock:         &lock,
		}

		tcpForwarder := gtcp.NewForwarder(s, 0, 65535, tcp.Handler(tcpConfig))
		s.SetTransportProtocolHandler(gtcp.ProtocolNumber, tcpForwarder.HandlePacket)
	}
	if cfg.EnableUDP {
		udpConfig := udp.Config{
			Tnet:      tnet,
			StackLock: &lock,
		}

		s.SetTransportProtocolHandler(gudp.ProtocolNumber, udp.Handler(udpConfig))
	}

	wgDevice.Up()

	return &WireGuardServer{
		tun:      tunDevice,
		tnet:     tnet,
		wgDevice: wgDevice,
	}, nil

}

func (wg *WireGuardServer) Close() {
	wg.wgDevice.Close()
	wg.tun.Close()
}

func (wg *WireGuardServer) AddPeer(PublicKey string, AllowedIPs []string) error {
	publickey, err := b64tohex(PublicKey)

	if err != nil {
		return err
	}

	setStr := "public_key=" + publickey + "\n"

	for _, ip := range AllowedIPs {
		setStr += "allowed_ip=" + ip + "\n"
	}

	err = wg.wgDevice.IpcSet(setStr)

	if err != nil {
		return err
	}

	return nil
}

func (wg *WireGuardServer) Up() error {
	return wg.wgDevice.Up()
}
