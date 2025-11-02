package net

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type Conn net.Conn

type ByteCounterConn struct {
	Tx, Rx *uint64
	net.Conn
}

func (bc *ByteCounterConn) Write(p []byte) (n int, e error) {
	n, e = bc.Conn.Write(p)
	atomic.AddUint64(bc.Tx, uint64(n))
	return
}
func (bc *ByteCounterConn) Read(p []byte) (n int, e error) {
	n, e = bc.Conn.Read(p)
	atomic.AddUint64(bc.Rx, uint64(n))
	return
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

func ConnSync(conn net.Conn, oconn net.Conn) {
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
	oconn.Close()
}

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
