package trojan

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/utils"
)

const MaxPacketSize = 65507

type UDPPacket struct {
	Payload []byte
	Address *net.UDPAddr
}

type Server struct {
	PasswordHashes []string
}

func (s *Server) Handle(conn *tcp.Conn) tcp.SerRet {
	buf := make([]byte, 58)

	var r = conn.TopConn()

	n, err := r.Read(buf)
	if err != nil {
		return tcp.Close
	}
	if n != 58 {
		return tcp.Close
	}

	hashes := buf[0:56]

	if !slices.Contains(s.PasswordHashes, string(hashes)) {
		return tcp.Close
	}

	var metadata Metadata
	err = metadata.ReadFrom(r)
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
		switch metadata.Address.AddressType {
		case IPv4:
			target, err = net.DialTCP("tcp", nil, &net.TCPAddr{
				IP:   metadata.Address.IP,
				Port: metadata.Address.Port,
			})
			log.Verboseln("[TROJAN]", "Dialed TCP4", metadata.Address.IP.String(), metadata.Address.Port)
		case IPv6:
			target, err = net.DialTCP("tcp6", nil, &net.TCPAddr{
				IP:   metadata.Address.IP,
				Port: metadata.Address.Port,
			})
			log.Verboseln("[TROJAN]", "Dialed TCP6", metadata.Address.IP.String(), metadata.Address.Port)
		case DomainName:
			target, err = net.Dial("tcp", net.JoinHostPort(metadata.Address.DomainName, strconv.Itoa(metadata.Address.Port)))
			log.Verboseln("[TROJAN]", "Dialed TCP", metadata.Address.DomainName, metadata.Address.Port)
		}

		if err != nil {
			log.Verboseln("[TROJAN]", " Dial failed", err)
			return tcp.Close
		}

		utils.ConnSync(r, target)
		return tcp.Close

	case 0x3: // Associate

		// Connection table to manage target UDP connections
		connTable := make(map[string]*net.UDPConn)
		newConnChan := make(chan *net.UDPConn, 10)

		// Channel to signal when forwarding should stop
		done := make(chan struct{}, 2)

		var muWrite sync.Mutex

		// Target to client forwarding
		go func() {
			defer func() { done <- struct{}{} }()

			// Keep track of active connections for reading
			activeConns := make(map[*net.UDPConn]bool)

			for {
				select {
				case newConn := <-newConnChan:
					// Add new connection to active connections
					activeConns[newConn] = true

					// Start goroutine to read from this specific connection
					go func(udpConn *net.UDPConn) {
						buf := make([]byte, MaxPacketSize)
						for {
							n, addr, err := udpConn.ReadFromUDP(buf)

							if err != nil {
								log.Verboseln("[TROJAN]", "ReadFromUDP failed", err)
								delete(activeConns, udpConn)
								udpConn.Close()
								return
							}

							// Create packet for forwarding
							payload := buf[:n]
							packet := make([]byte, 0, MaxPacketSize)
							w := bytes.NewBuffer(packet)

							// Create metadata for the source address
							var addrMetadata Address
							addrMetadata.IP = addr.IP
							addrMetadata.Port = addr.Port
							if addr.IP.To4() != nil {
								addrMetadata.AddressType = IPv4
							} else {
								addrMetadata.AddressType = IPv6
							}

							// Write address metadata
							if err := addrMetadata.WriteTo(w); err != nil {
								log.Verboseln("[TROJAN]", "Failed to write address metadata", err)
								continue
							}

							length := len(payload)
							lengthBuf := [2]byte{}
							crlf := [2]byte{0x0d, 0x0a}

							binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
							w.Write(lengthBuf[:])
							w.Write(crlf[:])
							w.Write(payload)

							// log.Verboseln("[TROJAN]", "UDP packet forwarded from", addr.String(), "size", length)

							muWrite.Lock()
							_, err = conn.TopConn().Write(w.Bytes())
							muWrite.Unlock()

							if err != nil {
								log.Verboseln("[TROJAN]", "Write to client failed", err)
								return
							}
						}
					}(newConn)

				case <-done:
					// Clean up all connections
					for udpConn := range activeConns {
						udpConn.Close()
					}
					return
				}
			}
		}()

		// Client to target forwarding
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				// Read address metadata from client
				addr := &Address{
					NetworkType: "udp",
				}
				if err := addr.ReadFrom(conn.TopConn()); err != nil {
					// log.Verboseln("[TROJAN]", "failed to parse udp packet addr", err)
					break
				}

				// Read length
				lengthBuf := [2]byte{}
				if _, err := io.ReadFull(conn.TopConn(), lengthBuf[:]); err != nil {
					break
				}
				length := int(binary.BigEndian.Uint16(lengthBuf[:]))

				// Read CRLF
				crlf := [2]byte{}
				if _, err := io.ReadFull(conn.TopConn(), crlf[:]); err != nil {
					break
				}

				// Validate packet size
				if length > MaxPacketSize {
					log.Verboseln("[TROJAN]", "incoming packet size is too large", length)
					io.CopyN(io.Discard, conn.TopConn(), int64(length)) // drain the rest of the packet
					continue
				}

				// Read payload
				payload := make([]byte, length)
				if _, err := io.ReadFull(conn.TopConn(), payload); err != nil {
					break
				}

				// Determine target address
				var targetAddr *net.UDPAddr
				var addrKey string

				switch addr.AddressType {
				case IPv4, IPv6:
					targetAddr = &net.UDPAddr{
						IP:   addr.IP,
						Port: addr.Port,
					}
					addrKey = targetAddr.String()
				case DomainName:
					// Resolve domain name
					resolvedAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr.DomainName, strconv.Itoa(addr.Port)))
					if err != nil {
						log.Verboseln("[TROJAN]", "failed to resolve domain", addr.DomainName, err)
						continue
					}
					targetAddr = resolvedAddr
					addrKey = net.JoinHostPort(addr.DomainName, strconv.Itoa(addr.Port))
				}

				// Get or create UDP connection for this target
				target, exists := connTable[addrKey]
				if !exists {
					var err error
					switch addr.AddressType {
					case IPv4:
						target, err = net.DialUDP("udp4", nil, targetAddr)
					case IPv6:
						target, err = net.DialUDP("udp6", nil, targetAddr)
					case DomainName:
						target, err = net.DialUDP("udp", nil, targetAddr)
					}

					if err != nil {
						log.Verboseln("[TROJAN]", "DialUDP failed for", addrKey, err)
						continue
					}

					connTable[addrKey] = target
					log.Verboseln("[TROJAN]", "Created new UDP connection to", addrKey)

					// Notify the target to client forwarding about the new connection
					select {
					case newConnChan <- target:
					default:
						log.Verboseln("[TROJAN]", "Failed to notify about new connection, channel full")
					}
				}

				// Forward packet to target
				_, err := target.Write(payload)
				if err != nil {
					log.Verboseln("[TROJAN]", "Write to UDP target failed for", addrKey, err)
					// Remove failed connection from table
					target.Close()
					delete(connTable, addrKey)
					continue
				}

				// log.Verboseln("[TROJAN]", "UDP packet forwarded to", targetAddr.String(), "size", length)
			}
		}()

		// Wait for one of the goroutines to finish (indicating an error or connection close)
		<-done

		// Clean up all connections in the table
		for _, target := range connTable {
			target.Close()
		}

		return tcp.Close

	}

	return tcp.Close

}
