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
type ServiceBinding struct {
	ServiceHandler
	Name string
}

type controller struct {
	binds map[string][]ServiceBinding

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
	s := c.binds[conn.protos]
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

		conn.AppendPath(v.Name + " ")

		timing := time.Now()

		ret = v.Handle(conn)

		conn.AppendPath(time.Since(timing).Round(10*time.Microsecond).String() + " ")

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

var listeners map[string]net.Listener = make(map[string]net.Listener)
var listenerlock sync.Mutex

func (ctl *controller) Listen(addr string) error {
	listenerlock.Lock()
	if lc, ok := listeners[addr]; ok {
		log.Verbosef("rebind tcp listen %s", addr)
		lc.Close()
	}

	lc, err := net.Listen("tcp", addr)
	if err != nil {
		listenerlock.Unlock()
		return err
	}

	listeners[addr] = lc

	listenerlock.Unlock()

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
				log.Errorf("%v", err)
				break
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

func (ctl *controller) Bind(protocol string, svcs ...ServiceBinding) {
	ctl.binds[protocol] = append(ctl.binds[protocol], svcs...)
}

func (ctl *controller) Report() map[uint64]interface{} {
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

func NewTcpController() *controller {
	return &controller{
		binds:              map[string][]ServiceBinding{},
		muActiveConnection: sync.RWMutex{},
		activeConnections:  map[uint64]*Conn{},
	}
}
