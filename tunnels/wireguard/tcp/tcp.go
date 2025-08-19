// Package tcp proxies TCP connections between a WireGuard peer and a destination
// accessible by the machine where Wiretap is running.
//
// Adapted from https://github.com/tailscale/tailscale/blob/2cf6e127907641bdb9eb5cd8e8cf14e968b571d7/wgengine/netstack/netstack.go
// Adapted from https://github.com/sandialabs/wiretap/blob/21e6aba408e2fd3a059fa299ee040f1ff2ea7293/src/transport/tcp/tcp.go
// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tcp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"net/netip"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/utils"
	"github.com/mrhaoxx/OpenNG/wireguard/netstack"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Configure TCP handler.
type Config struct {
	CatchTimeout      time.Duration
	ConnTimeout       time.Duration
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int
	Tnet              *netstack.Net
	StackLock         *sync.Mutex
}

// Handler manages a single TCP flow.
func Handler(c Config) func(*tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		// Received TCP flow, add address so we can work with it.
		s := req.ID()

		now := time.Now()
		path := fmt.Sprintf("wg %s TCP -> %s", net.JoinHostPort(s.RemoteAddress.String(), fmt.Sprint(s.RemotePort)), net.JoinHostPort(s.LocalAddress.String(), fmt.Sprint(s.LocalPort)))

		// Add address to stack.
		addr, _ := netip.AddrFromSlice(s.LocalAddress.AsSlice())
		err := c.Tnet.AddAddress(addr, c.Tnet.Stack(), c.StackLock)
		if err != nil {
			log.Println("failed to add address: ", err)
			req.Complete(false)
			return
		}

		defer func() {
			err := c.Tnet.RemoveAddress(addr, c.Tnet.Stack(), c.StackLock)
			if err != nil {
				log.Verbosef("[wireguard] failed to remove address: %v", err)
			}
		}()

		path += fmt.Sprintf(" prep %s", time.Since(now))
		now = time.Now()

		// Address is added, now test if remote endpoint is available.
		dstConn, rst := checkDst(&c, s)
		if dstConn == nil {
			req.Complete(rst)
			return
		}

		defer dstConn.Close()

		path += fmt.Sprintf(" remote %s", time.Since(now))
		now = time.Now()

		// Accept conn.
		srcConn, err := accept(&c, req)
		if err != nil {
			dstConn.Close()
			log.Verbosef("[wireguard] failed to create endpoint: %v", err)
			return
		}
		defer srcConn.Close()

		// utils.ConnSync(dstConn, srcConn)
		utils.ConnSync(srcConn, dstConn)

		path += fmt.Sprintf(" accept %s", time.Since(now))

		log.Println(path)
	}
}

// checkDst determines if a tcp connection can be made to a destination.
// Returns the connection on success,
// a channel for the caller to populate when the connection is used,
// and whether or not to send RST to source.
func checkDst(config *Config, s stack.TransportEndpointID) (net.Conn, bool) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(s.LocalAddress.String(), fmt.Sprint(s.LocalPort)), config.ConnTimeout)

	if err != nil {
		// If connection refused, we can send a reset to let peer know.
		if oerr, ok := err.(*net.OpError); ok {
			if syserr, ok := oerr.Err.(*os.SyscallError); ok {
				if syserr.Err == syscall.ECONNREFUSED {
					return nil, true
				}
			}
		}

		log.Verbosef("[wireguard] failed to connect to %s: %v", net.JoinHostPort(s.LocalAddress.String(), fmt.Sprint(s.LocalPort)), err)
		return nil, true
	}

	// Start "catch" timer to make sure connection is actually used.
	// caughtChan := make(chan bool)
	// go func() {
	// 	select {
	// 	case <-time.After(config.CatchTimeout):
	// 		c.Close()
	// 	case <-caughtChan:
	// 	}
	// }()

	// return c, caughtChan, false
	return c, false
}

// accept converts a forwarder request to an endpoint, sets sockopts, then converts to conn.
// "Completes" forwarding request without RST.
func accept(c *Config, req *tcp.ForwarderRequest) (*gonet.TCPConn, error) {
	// We want to accept this flow, setup endpoint to complete handshake.
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	req.Complete(false)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Enable keepalive and set defaults so that after (idle + (count * interval)) connection will be dropped if unresponsive.
	ep.SocketOptions().SetKeepAlive(true)
	keepaliveIdle := tcpip.KeepaliveIdleOption(c.KeepaliveIdle)
	err = ep.SetSockOpt(&keepaliveIdle)
	if err != nil {
		return nil, errors.New(err.String())
	}
	keepaliveInterval := tcpip.KeepaliveIntervalOption(c.KeepaliveInterval)
	err = ep.SetSockOpt(&keepaliveInterval)
	if err != nil {
		return nil, errors.New(err.String())
	}
	err = ep.SetSockOptInt(tcpip.KeepaliveCountOption, c.KeepaliveCount)
	if err != nil {
		return nil, errors.New(err.String())
	}

	return gonet.NewTCPConn(&wq, ep), nil
}
