package tcp

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utils "github.com/mrhaoxx/OpenNG/utils"
)

//ng:generate def obj Connection
type Conn struct {
	//unsync \ atomic
	Id    string
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
	ip     string
	port   int
	protos string
	path   string

	mu sync.RWMutex
}

func (c *Conn) Addr() net.Addr {
	return c.addr
}

func (c *Conn) IP() string {
	return c.ip
}
func (c *Conn) Port() int {
	return c.port
}

func (c *Conn) TopConn() net.Conn {
	return c.conn[c.head]
}
func (c *Conn) TopProtocol() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.proto[c.head]
}
func (c *Conn) unsync_genProtocols() {
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

func (c *Conn) unsync_genAddr() {
	ip, port, _ := net.SplitHostPort(c.addr.String())
	c.ip = ip
	c.port, _ = strconv.Atoi(port)
}

func (c *Conn) Protocols() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.protos
}

func (c *Conn) Path() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.path
}

func (c *Conn) AppendPath(n string) {
	c.mu.Lock()
	c.path += n
	c.mu.Unlock()
}

func (c *Conn) Upgrade(nc net.Conn, protocol string) {
	//async
	c.head += 1
	c.conn = append(c.conn, nc)
	c.proto = append(c.proto, protocol)

	//sync
	c.mu.Lock()
	c.addr = nc.RemoteAddr()
	c.unsync_genAddr()
	c.unsync_genProtocols()
	c.mu.Unlock()
}

func (c *Conn) IdentifiyProtocol(protocol string) {
	c.proto[c.head] = protocol

	c.mu.Lock()
	c.unsync_genProtocols()
	c.mu.Unlock()
}

func (c *Conn) Reuse(conn net.Conn) {
	c.conn[c.head] = conn

	c.mu.Lock()
	c.addr = conn.RemoteAddr()
	c.unsync_genAddr()
	c.mu.Unlock()
}

func (c *Conn) Close() {
	close(c.closing)
	c.conn[c.head].Close()
}
func (c *Conn) IsClosing() <-chan struct{} {
	return c.closing
}

func (c *Conn) triggerConnectionClose() {
	c.conn[c.head].Close()
}

var cur uint64 = 1

const InitProtocolLayer = 4

func newConnID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func head(cn net.Conn) *Conn {
	atomic.AddUint64(&cur, 1)
	p := &Conn{
		Id:      newConnID(),
		conn:    make([]net.Conn, 0, InitProtocolLayer),
		proto:   make([]string, 0, InitProtocolLayer),
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
