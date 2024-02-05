package tcp

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
)

const (
	Continue SerRet = iota
	Close
	Upgrade
)

type SerRet uint8

type ServiceHandler interface {
	Handle(*Conn) SerRet
}
type SericeBinding struct {
	ServiceHandler
	name string
}

type controller struct {
	Services map[string]ServiceHandler
	Binds    map[string][]SericeBinding

	listeners []*net.Listener

	muActiveConnection sync.RWMutex
	activeConnections  map[uint64]*Conn
}

func (c *controller) Deliver(conn *Conn) {

	c.muActiveConnection.Lock()
	c.activeConnections[conn.Id] = conn
	c.muActiveConnection.Unlock()

	defer func() { // cleanup
		conn.AppendPath("-")
		c.muActiveConnection.Lock()
		delete(c.activeConnections, conn.Id)
		c.muActiveConnection.Unlock()
		conn.Close()
		log.Println(
			"c"+strconv.FormatUint(conn.Id, 10),
			conn.Addr().String(),
			time.Since(conn.start).Round(10*time.Microsecond),
			atomic.LoadUint64(&conn.bytesrx), atomic.LoadUint64(&conn.bytestx),
			conn.protos,
			conn.path,
		)
	}()

_restart:
	s := c.Binds[conn.protos]
	var ret SerRet

	defer func() {
		if err := recover(); err != nil {
			if e, ok := err.(error); ok {
				conn.AppendPath("$<" + e.Error() + "> ")
			} else {
				conn.AppendPath("$<> ")
			}
			ret = Close
		}
	}()

	for _, v := range s {

		ret = v.Handle(conn)

		conn.AppendPath(v.name + " ")

		switch ret {
		case Close:
			return
		case Upgrade:
			conn.AppendPath("+ ")
			goto _restart
		case Continue:
			continue
		}

	}

}

func (ctl *controller) Listen(addr string) error {
	lc, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ctl.listeners = append(ctl.listeners, &lc)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
			}
		}()
		for {
			socket, err := lc.Accept()
			if err != nil {
				if err == net.ErrClosed {
					break
				}
				panic(err)
			}
			go func() {
				i := head(socket)
				ctl.Deliver(i)
			}()
		}
	}()
	return nil
}

type funcInterface func(*Conn) SerRet

func (f funcInterface) Handle(a *Conn) SerRet {
	return f(a)
}

func NewServiceFunction(f func(*Conn) SerRet) ServiceHandler {
	return funcInterface(f)
}

func (ctl *controller) Bind(protocol string, services []string) error {

	var bindings []SericeBinding
	for _, g := range services {
		s, ok := ctl.Services[g]
		if !ok {
			return errors.New("service " + g + " not found")
		}
		bindings = append(bindings, SericeBinding{
			name:           g,
			ServiceHandler: s,
		})
	}
	ctl.Binds[protocol] = bindings
	return nil
}

func (ctl *controller) AddService(name string, handler ServiceHandler) {
	ctl.Services[name] = handler
}

func (ctl *controller) ReportActiveConnections() map[uint64]interface{} {
	ctl.muActiveConnection.RLock()
	defer ctl.muActiveConnection.RUnlock()
	ret := make(map[uint64]interface{})
	for _, conn := range ctl.activeConnections {
		ret[conn.Id] = map[string]interface{}{
			"src":       conn.Addr().String(),
			"starttime": conn.start,
			"protocols": conn.Protocols(),
			"path":      conn.Path(),
			"bytesrx":   atomic.LoadUint64(&conn.bytesrx),
			"bytestx":   atomic.LoadUint64(&conn.bytestx),
		}
	}
	return ret
}

func (ctl *controller) KillConnection(connection_id uint64) error {
	ctl.muActiveConnection.RLock()
	defer ctl.muActiveConnection.RUnlock()
	conn, ok := ctl.activeConnections[connection_id]
	if !ok {
		return errors.New("connection not found")
	}
	conn.AppendPath(">! ")
	conn.triggerConnectionClose()
	return nil
}

func NewTcpController(services map[string]ServiceHandler) *controller {
	return &controller{
		Services:           services,
		Binds:              map[string][]SericeBinding{},
		muActiveConnection: sync.RWMutex{},
		activeConnections:  map[uint64]*Conn{},
	}
}
