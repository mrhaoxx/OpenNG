package ngtcp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	zlog "github.com/rs/zerolog/log"
)

const (
	Continue Ret = iota
	Close
	Upgrade
)

type Ret uint8

type Service interface {
	HandleTCP(*Conn) Ret
}

type ServiceBinding struct {
	Service `ng:"logi" desc:"pointer to service"`
	Name    string `ng:"name" desc:"name of the service handler"`
}

type Controller struct {
	binds map[string][]ServiceBinding

	listeners []*net.Listener

	muActiveConnection sync.RWMutex
	activeConnections  map[string]*Conn
}

func (c *Controller) Deliver(conn *Conn) {

	c.muActiveConnection.Lock()
	c.activeConnections[conn.Id] = conn
	c.muActiveConnection.Unlock()

	defer func() { // cleanup
		conn.AppendPath("-")
		c.muActiveConnection.Lock()
		delete(c.activeConnections, conn.Id)
		c.muActiveConnection.Unlock()
		conn.Close()
		// log.Println(
		// 	"c"+strconv.FormatUint(conn.Id, 10),
		// 	conn.Addr().String(),
		// 	time.Since(conn.start).Round(10*time.Microsecond),
		// 	atomic.LoadUint64(&conn.bytesrx), atomic.LoadUint64(&conn.bytestx),
		// 	conn.protos,
		// 	conn.path,
		// )
		zlog.Info().
			Str("conn", conn.Id).
			Str("ip", conn.IP()).
			Int("port", conn.Port()).
			Dur("duration", time.Since(conn.start)).
			Uint64("rx", atomic.LoadUint64(&conn.bytesrx)).
			Uint64("tx", atomic.LoadUint64(&conn.bytestx)).
			Strs("protocols", conn.proto).
			Str("routine", conn.path).
			Str("type", "tcp/conn").Msg("")
	}()

_restart:
	s := c.binds[conn.protos]
	var ret Ret

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

		ret = v.HandleTCP(conn)

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

func (ctl *Controller) Listen(addrs []string) error {
	for _, addr := range addrs {
		listenerlock.Lock()
		if lc, ok := listeners[addr]; ok {
			zlog.Warn().Str("type", "tcp/listen").Str("addr", addr).Msg("rebind tcp listen")
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
					zlog.Error().Str("type", "tcp/listen").Interface("err", err).Msg("tcp listen panic")
				}
			}()
			for {
				socket, err := lc.Accept()
				if err != nil {
					zlog.Error().Str("type", "tcp/listen").Interface("err", err).Msg("tcp listen accept")
					break
				}

				go func() {
					i := head(socket)
					ctl.Deliver(i)
				}()
			}
		}()
	}
	return nil
}

type funcInterface func(*Conn) Ret

func (f funcInterface) HandleTCP(a *Conn) Ret {
	return f(a)
}

func NewServiceFunction(f func(*Conn) Ret) Service {
	return funcInterface(f)
}

func (ctl *Controller) Bind(protocol string, svcs ...ServiceBinding) {
	ctl.binds[protocol] = append(ctl.binds[protocol], svcs...)
}

func (ctl *Controller) Report() (map[string]interface{}, error) {
	ctl.muActiveConnection.RLock()
	defer ctl.muActiveConnection.RUnlock()
	ret := make(map[string]interface{})
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
	return ret, nil
}

func (ctl *Controller) KillConnection(connection_id string) error {
	ctl.muActiveConnection.RLock()
	defer ctl.muActiveConnection.RUnlock()
	conn, ok := ctl.activeConnections[connection_id]
	if !ok {
		return errors.New("connection not found " + connection_id)
	}
	conn.AppendPath(">! ")
	conn.triggerConnectionClose()
	return nil
}

type TcpControllerConfig struct {
	Services map[string][]ServiceBinding `ng:"services" desc:"protocol-specific service handlers, where key is the protocol name (e.g. '' (first inbound), 'TLS', 'HTTP1', 'TLS HTTP2', etc)"`
}

func NewTcpController(cfg TcpControllerConfig) (*Controller, error) {
	ctl := &Controller{
		binds:              map[string][]ServiceBinding{},
		muActiveConnection: sync.RWMutex{},
		activeConnections:  map[string]*Conn{},
	}

	for protocol, svcs := range cfg.Services {
		ctl.binds[protocol] = append(ctl.binds[protocol], svcs...)
	}

	return ctl, nil
}
