package logging

import (
	"net"
)

type udpLogger struct {
	*net.UDPConn
}

//	func (I *udpLogger) Write(byt []byte) (int, error) {
//		 I.UDPConn.Write(byt)
//		return 0, nil
//	}
func NewUdpLogger(cfg UdpLoggerConfig) *udpLogger {
	addr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}
	return &udpLogger{UDPConn: conn}
}

type UdpLoggerConfig struct {
	Address string `yaml:"Address"`
}
