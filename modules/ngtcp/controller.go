package ngtcp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	zlog "github.com/rs/zerolog/log"

	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/mrhaoxx/OpenNG/pkg/stats"
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

	releases []func() // listener registry releases, one per acquired address

	muActiveConnection sync.RWMutex
	activeConnections  map[string]*Conn

	// Aggregate stats (lock-free)
	TotalConns  stats.Counter
	ActiveConns stats.Counter
	TotalRx     stats.Counter
	TotalTx     stats.Counter
	ConnRate    stats.RateWindow
}

func (c *Controller) Deliver(conn *Conn) {
	c.TotalConns.Inc()
	c.ActiveConns.Add(1)
	c.ConnRate.Inc()

	c.muActiveConnection.Lock()
	c.activeConnections[conn.Id] = conn
	c.muActiveConnection.Unlock()

	defer func() { // cleanup
		conn.AppendPath("-")
		c.muActiveConnection.Lock()
		delete(c.activeConnections, conn.Id)
		c.muActiveConnection.Unlock()

		// Accumulate bytes before closing
		rx := atomic.LoadUint64(&conn.bytesrx)
		tx := atomic.LoadUint64(&conn.bytestx)
		c.TotalRx.Add(rx)
		c.TotalTx.Add(tx)
		c.ActiveConns.Add(^uint64(0)) // decrement

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

// Listen acquires each address on the process-wide listener registry; this
// controller becomes the active receiver, and the previous holder (an older
// generation during reload) resumes if this one is stopped.
func (ctl *Controller) Listen(addrs []string) error {
	for _, addr := range addrs {
		release, err := ngnet.AcquireListener("tcp", addr, func(socket net.Conn) {
			ctl.Deliver(head(socket))
		})
		if err != nil {
			return err
		}
		ctl.releases = append(ctl.releases, release)
	}
	return nil
}

// Stop hands this controller's addresses back to the listener registry.
// Established connections are left to drain naturally.
func (ctl *Controller) Stop() {
	for _, release := range ctl.releases {
		release()
	}
	ctl.releases = nil
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
	Services map[string][]ServiceBinding `ng:"services" desc:"protocol-specific service handlers"`
	Listen   []string                    `ng:"listen" desc:"addresses to listen on (e.g. 0.0.0.0:443)"`
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

	if len(cfg.Listen) > 0 {
		if err := ctl.Listen(cfg.Listen); err != nil {
			return nil, err
		}
	}

	return ctl, nil
}
