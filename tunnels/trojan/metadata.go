package trojan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type Command byte

type AddressType byte

type Metadata struct {
	Command
	*Address
}

const (
	IPv4       AddressType = 1
	DomainName AddressType = 3
	IPv6       AddressType = 4
)

type Address struct {
	DomainName string
	Port       int
	net.IP
	AddressType
}

func (r *Metadata) unmarshal(rr io.Reader) error {
	byteBuf := [1]byte{}
	_, err := io.ReadFull(rr, byteBuf[:])
	if err != nil {
		return err
	}
	r.Command = Command(byteBuf[0])
	r.Address = new(Address)
	err = r.Address.unmarshal(rr)
	if err != nil {
		return errors.New("failed to parse address")
	}
	return nil
}

func (a *Address) unmarshal(r io.Reader) error {
	byteBuf := [1]byte{}
	_, err := io.ReadFull(r, byteBuf[:])
	if err != nil {
		return fmt.Errorf("unable to read ATYP: %w", err)
	}
	a.AddressType = AddressType(byteBuf[0])
	switch a.AddressType {
	case IPv4:
		var buf [6]byte
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return fmt.Errorf("failed to read IPv4: %w", err)
		}
		a.IP = buf[0:4]
		a.Port = int(binary.BigEndian.Uint16(buf[4:6]))
	case IPv6:
		var buf [18]byte
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return fmt.Errorf("failed to read IPv6: %w", err)
		}
		a.IP = buf[0:16]
		a.Port = int(binary.BigEndian.Uint16(buf[16:18]))
	case DomainName:
		_, err := io.ReadFull(r, byteBuf[:])
		length := byteBuf[0]
		if err != nil {
			return fmt.Errorf("failed to read domain name length: %w", err)
		}
		buf := make([]byte, length+2)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return fmt.Errorf("failed to read domain name: %w", err)
		}
		host := buf[0:length]
		if ip := net.ParseIP(string(host)); ip != nil {
			a.IP = ip
			if ip.To4() != nil {
				a.AddressType = IPv4
			} else {
				a.AddressType = IPv6
			}
		} else {
			a.DomainName = string(host)
		}
		a.Port = int(binary.BigEndian.Uint16(buf[length : length+2]))
	default:
		return fmt.Errorf("invalid ATYP %s", strconv.FormatInt(int64(a.AddressType), 10))
	}
	return nil
}

func (a *Address) marshal(w io.Writer) error {
	_, err := w.Write([]byte{byte(a.AddressType)})
	if err != nil {
		return err
	}
	switch a.AddressType {
	case DomainName:
		w.Write([]byte{byte(len(a.DomainName))})
		_, err = w.Write([]byte(a.DomainName))
	case IPv4:
		_, err = w.Write(a.IP.To4())
	case IPv6:
		_, err = w.Write(a.IP.To16())
	default:
		return fmt.Errorf("invalid ATYP %s", strconv.FormatInt(int64(a.AddressType), 10))
	}
	if err != nil {
		return err
	}
	port := [2]byte{}
	binary.BigEndian.PutUint16(port[:], uint16(a.Port))
	_, err = w.Write(port[:])
	return err
}
