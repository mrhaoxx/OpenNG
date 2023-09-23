package utils

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//########################
//#  Connection  Utils   #
//########################

func ConnSync(conn net.Conn, oconn net.Conn) {
	//log.Println("[ConnSync]", (*conn).RemoteAddr(), " <-> ", oconn.RemoteAddr())
	c1 := make(chan uint8)
	c2 := make(chan uint8)
	go func() {
		_, _ = io.Copy(conn, oconn)
		close(c1)
	}()
	go func() {
		_, _ = io.Copy(oconn, conn)
		_ = oconn.Close()
		close(c2)
	}()
	select {
	case <-c1:
	case <-c2:
	}
	_ = oconn.Close()
	//log.Println("[ConnSync]", (*conn).RemoteAddr(), " !!! ", oconn.RemoteAddr())
}

// func (c *Recorededudps) SyscallConn() (syscall.RawConn, error) {
// 	return c.UDPConn.SyscallConn()
// }

// func (c *Recorededudps) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
// 	n, addr, err = c.UDPConn.ReadFromUDP(b)
// 	c.ByteCounter.AddRx(uint64(n))
// 	return
// }

// func (c *Recorededudps) ReadFrom(b []byte) (int, net.Addr, error) {
// 	n, addr, err := c.UDPConn.ReadFrom(b)
// 	c.ByteCounter.AddRx(uint64(n))
// 	return n, addr, err
// }

// func (c *Recorededudps) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
// 	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
// 	c.ByteCounter.AddRx(uint64(n))
// 	return
// }

// func (c *Recorededudps) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
// 	n, err := c.UDPConn.WriteToUDP(b, addr)
// 	c.ByteCounter.AddTx(uint64(n))
// 	return n, err
// }
// func (c *Recorededudps) WriteTo(b []byte, addr net.Addr) (int, error) {
// 	n, err := c.UDPConn.WriteTo(b, addr)
// 	c.ByteCounter.AddTx(uint64(n))
// 	return n, err
// }

// func (c *Recorededudps) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
// 	n, oobn, err = c.UDPConn.WriteMsgUDP(b, oob, addr)
// 	c.ByteCounter.AddTx(uint64(n))
// 	return
// }
// func (c *Recorededudps) Close() error {
// 	return c.UDPConn.Close()
// }
// func (c *Recorededudps) LocalAddr() net.Addr {
// 	return c.UDPConn.LocalAddr()
// }
// func (c *Recorededudps) RemoteAddr() net.Addr {
// 	return c.UDPConn.RemoteAddr()
// }
// func (c *Recorededudps) File() (f *os.File, err error) {
// 	return c.UDPConn.File()
// }
// func (c *Recorededudps) Read(b []byte) (n int, e error) {
// 	n, e = c.UDPConn.Read(b)
// 	c.ByteCounter.AddRx(uint64(n))
// 	return
// }
// func (c *Recorededudps) SetDeadline(t time.Time) error {
// 	return c.UDPConn.SetDeadline(t)
// }
// func (c *Recorededudps) SetReadBuffer(bytes int) error {
// 	return c.UDPConn.SetReadBuffer(bytes)
// }
// func (c *Recorededudps) SetReadDeadline(t time.Time) error {
// 	return c.UDPConn.SetReadDeadline(t)
// }
// func (c *Recorededudps) SetWriteBuffer(bytes int) error {
// 	return c.UDPConn.SetWriteBuffer(bytes)
// }
// func (c *Recorededudps) SetWriteDeadline(t time.Time) error {
// 	return c.UDPConn.SetWriteDeadline(t)
// }
// func (c *Recorededudps) Write(b []byte) (n int, e error) {
// 	n, e = c.UDPConn.Write(b)
// 	c.ByteCounter.AddTx(uint64(n))
// 	return
// }

type RoConn struct {
	Reader io.Reader
}

func (conn *RoConn) Read(p []byte) (int, error)       { return conn.Reader.Read(p) }
func (conn *RoConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn *RoConn) Close() error                     { return nil }
func (conn *RoConn) LocalAddr() net.Addr              { return nil }
func (conn *RoConn) RemoteAddr() net.Addr             { return nil }
func (conn *RoConn) SetDeadline(time.Time) error      { return nil }
func (conn *RoConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *RoConn) SetWriteDeadline(time.Time) error { return nil }

type RwConn struct {
	Reader  io.Reader
	Writer  io.Writer
	Rawconn net.Conn
}

func (conn *RwConn) Read(p []byte) (int, error)         { return conn.Reader.Read(p) }
func (conn *RwConn) Write(p []byte) (int, error)        { return conn.Writer.Write(p) }
func (conn *RwConn) Close() error                       { return conn.Rawconn.Close() }
func (conn *RwConn) LocalAddr() net.Addr                { return conn.Rawconn.LocalAddr() }
func (conn *RwConn) RemoteAddr() net.Addr               { return conn.Rawconn.RemoteAddr() }
func (conn *RwConn) SetDeadline(t time.Time) error      { return conn.Rawconn.SetDeadline(t) }
func (conn *RwConn) SetReadDeadline(t time.Time) error  { return conn.Rawconn.SetReadDeadline(t) }
func (conn *RwConn) SetWriteDeadline(t time.Time) error { return conn.Rawconn.SetWriteDeadline(t) }

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type OneConn struct {
	conn   net.Conn
	done   chan struct{}
	closed bool
}

func (conn *OneConn) Read(p []byte) (i int, e error) {
	i, e = conn.conn.Read(p)
	if (e == io.EOF || e == io.ErrUnexpectedEOF) && !conn.closed {
		conn.closed = true
		close(conn.done)
	}
	return
}
func (conn *OneConn) Write(p []byte) (int, error) { return conn.conn.Write(p) }
func (conn *OneConn) Close() error {
	if !conn.closed {
		conn.closed = true
		close(conn.done)
	}
	return conn.conn.Close()
}
func (conn *OneConn) LocalAddr() net.Addr                { return conn.conn.LocalAddr() }
func (conn *OneConn) RemoteAddr() net.Addr               { return conn.conn.RemoteAddr() }
func (conn *OneConn) SetDeadline(t time.Time) error      { return conn.conn.SetDeadline(t) }
func (conn *OneConn) SetReadDeadline(t time.Time) error  { return conn.conn.SetReadDeadline(t) }
func (conn *OneConn) SetWriteDeadline(t time.Time) error { return conn.conn.SetWriteDeadline(t) }

type SingleConnListener struct {
	conn net.Conn
	done chan struct{}
	used bool
}

func (l *SingleConnListener) Accept() (net.Conn, error) {
	if l.used {
		<-l.done
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}

func (l *SingleConnListener) Close() error {
	return nil
}

func (l *SingleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
func ConnGetSocket(c net.Conn) (l *SingleConnListener) {
	cn := make(chan struct{})
	return &SingleConnListener{
		conn: &OneConn{
			conn: c,
			done: cn,
		},
		done: cn,
		used: false,
	}
}
func ByteCountSI(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

func RandString(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func TrimLeftChar(s string) string {
	for i := range s {
		if i > 0 {
			return s[i:]
		}
	}
	return s[:0]
}
