package utils

import (
	"net"
	"sync/atomic"
)

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
