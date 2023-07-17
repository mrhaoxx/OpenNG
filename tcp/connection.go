package tcp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	utils "github.com/haoxingxing/OpenNG/utils"
)

//ng:generate def obj Connection
type Connection struct {
	//unsync \ atomic
	Id    uint64
	conn  []net.Conn
	proto []string
	start time.Time

	head int8

	bytesrx uint64
	bytestx uint64

	//communication
	closing chan struct{}
	utils.Context

	//sync(lock)
	addr   net.Addr
	protos string
	path   string

	mu sync.RWMutex
}

func (c *Connection) Addr() net.Addr {
	return c.addr
}

func (c *Connection) TopConn() net.Conn {
	return c.conn[c.head]
}
func (c *Connection) TopProtocol() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.proto[c.head]
}
func (c *Connection) unsync_genProtocols() {
	c.protos = ""
	for _, v := range c.proto {
		if v != "" {
			c.protos += v + " "
		}
	}
	if c.protos != "" {
		c.protos = c.protos[:len(c.protos)-1]
	}
}

func (c *Connection) Protocols() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.protos
}

func (c *Connection) Path() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.path
}

func (c *Connection) AppendPath(n string) {
	c.mu.Lock()
	c.path += n
	c.mu.Unlock()
}

func (c *Connection) Upgrade(nc net.Conn, protocol string) {
	//async
	c.head += 1
	c.conn[c.head] = nc
	c.proto[c.head] = protocol

	//sync
	c.mu.Lock()
	c.addr = nc.RemoteAddr()
	c.unsync_genProtocols()
	c.mu.Unlock()
}

func (c *Connection) IdentifiyProtocol(protocol string) {
	c.proto[c.head] = protocol

	c.mu.Lock()
	c.unsync_genProtocols()
	c.mu.Unlock()
}

func (c *Connection) Reuse(conn net.Conn) {
	c.conn[c.head] = conn

	c.mu.Lock()
	c.addr = conn.RemoteAddr()
	c.mu.Unlock()
}

func (c *Connection) Close() {
	close(c.closing)
	c.conn[c.head].Close()
}
func (c *Connection) IsClosing() <-chan struct{} {
	return c.closing
}

func (c *Connection) triggerConnectionClose() {
	c.conn[c.head].Close()
}

var cur uint64 = 1

const InitProtocolLayer = 4

func head(cn net.Conn) *Connection {
	p := &Connection{
		Id:      atomic.AddUint64(&cur, 1) - 1,
		conn:    make([]net.Conn, InitProtocolLayer),
		proto:   make([]string, InitProtocolLayer),
		head:    -1,
		start:   time.Now(),
		bytesrx: 0,
		bytestx: 0,
		closing: make(chan struct{}),
		Context: &mainCtx{},
	}

	p.Upgrade(&utils.ByteCounterConn{
		Tx:   &p.bytestx,
		Rx:   &p.bytesrx,
		Conn: cn,
	}, "")

	return p
}
