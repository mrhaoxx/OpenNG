package trojan

import (
	"bytes"
	"encoding/binary"
	"io"
	gonet "net"
	"slices"
	"strconv"
	"sync"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/net"
	"github.com/mrhaoxx/OpenNG/tcp"

	"github.com/mrhaoxx/OpenNG/utils"
)

const MaxPacketSize = 65507

type UDPPacket struct {
	Payload []byte
	Address *gonet.UDPAddr
}

type Server struct {
	PasswordHashes []string
	Underlying     net.Interface

	initOnce sync.Once
}

func (s *Server) Handle(conn *tcp.Conn) tcp.SerRet {
	s.initOnce.Do(func() {
		if s.Underlying == nil {
			s.Underlying = net.DefaultRouteTable
		}
	})

	buf := make([]byte, 58)

	var r = conn.TopConn()

	n, err := r.Read(buf)

	if err != nil || n != 58 {
		return tcp.Close
	}

	hashes := buf[0:56]

	if !slices.Contains(s.PasswordHashes, string(hashes)) {
		return tcp.Close
	}

	var metadata Metadata
	err = metadata.unmarshal(r)
	if err != nil {
		return tcp.Close
	}

	var crlf [2]byte
	if _, err := io.ReadFull(r, crlf[:]); err != nil || crlf != [2]byte{0x0d, 0x0a} {
		return tcp.Close
	}
	switch metadata.Command {
	case 0x1: // Connect
		var target net.Conn
		var address string
		switch metadata.Address.AddressType {
		case IPv4, IPv6:
			address = gonet.JoinHostPort(metadata.Address.IP.String(), strconv.Itoa(metadata.Address.Port))
		case DomainName:
			address = gonet.JoinHostPort(metadata.Address.DomainName, strconv.Itoa(metadata.Address.Port))
		}

		target, err = s.Underlying.Dial("tcp", address)
		log.Verboseln("[TROJAN]", "Dialed TCP", address)

		if err != nil {
			log.Verboseln("[TROJAN]", "Dial failed", err)
			return tcp.Close
		}

		utils.ConnSync(r, target)
		return tcp.Close

	case 0x3: // Associate
		connTable := make(map[string]*gonet.UDPConn)

		var muWrite sync.Mutex

		var downlink = func(udpConn *gonet.UDPConn) {
			defer udpConn.Close()

			buf := make([]byte, MaxPacketSize)
			packet := make([]byte, 0, MaxPacketSize*2)
			w := bytes.NewBuffer(packet)

			for {
				n, addr, err := udpConn.ReadFromUDP(buf)

				if err != nil {
					return
				}

				payload := buf[:n]

				var addrMetadata = Address{
					IP:   addr.IP,
					Port: addr.Port,
				}

				if len(addr.IP) == gonet.IPv4len {
					addrMetadata.AddressType = IPv4
				} else {
					addrMetadata.AddressType = IPv6
				}

				if err := addrMetadata.marshal(w); err != nil {
					continue
				}

				length := uint16(len(payload))

				lengthcrlf := [4]byte{byte(length >> 8), byte(length), 0x0d, 0x0a}

				w.Write(lengthcrlf[:])
				w.Write(payload)

				// log.Verboseln("[TROJAN]", "UDP packet forwarded from", addr.String(), "size", length)

				muWrite.Lock()
				_, err = r.Write(w.Bytes())
				muWrite.Unlock()

				if err != nil {
					return
				}

				w.Reset()
			}
		}

		buf := make([]byte, MaxPacketSize)
		for {
			addr := &Address{}

			if err := addr.unmarshal(r); err != nil {
				break
			}

			lengthBuf := [4]byte{}
			if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
				break
			}
			length := int(binary.BigEndian.Uint16(lengthBuf[:]))

			if length > MaxPacketSize {
				io.CopyN(io.Discard, r, int64(length))
				continue
			}

			// Determine target address
			var address string

			switch addr.AddressType {
			case IPv4, IPv6:
				address = gonet.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
			case DomainName:
				address = gonet.JoinHostPort(addr.DomainName, strconv.Itoa(addr.Port))
			}

			target, exists := connTable[address]
			if !exists {
				_target, err := s.Underlying.Dial("udp", address)

				if err != nil {
					log.Verboseln("[TROJAN]", "DialUDP failed for", address, err)
					continue
				}

				target = _target.(*gonet.UDPConn)

				connTable[address] = target
				go downlink(target)

				log.Verboseln("[TROJAN]", "new UDP connection to", address)
			}

			n, err := io.ReadFull(r, buf[:length])

			if err != nil {
				log.Verboseln("[TROJAN]", "Read from client failed", err)
				break
			}

			_, err = target.Write(buf[:n])

			if err != nil {
				target.Close()
				delete(connTable, address)
				continue
			}

			// log.Verboseln("[TROJAN]", "UDP packet forwarded to", targetAddr.String(), "size", length)
		}

		for _, target := range connTable {
			target.Close()
		}

		return tcp.Close

	}

	return tcp.Close

}
