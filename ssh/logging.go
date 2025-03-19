package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"

	ssh "golang.org/x/crypto/ssh"
)

type SSHLogger struct{}

func (SSHLogger) HandleConn(ctx *Ctx) Ret {
	ctx.sshconn = &SSHWrappedConn{realconn: ctx.sshconn}

	var ncc chan ssh.NewChannel = make(chan ssh.NewChannel)
	var nc = ctx.nc
	ctx.nc = ncc

	go func() {
		for ch := range nc {
			ncc <- &SSHWrappedNewChannel{realchannel: ch}
		}
	}()

	return Continue
}

type SSHWrappedConn struct {
	realconn ssh.Conn
}

func (c *SSHWrappedConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return c.realconn.SendRequest(name, wantReply, payload)
}

func (c *SSHWrappedConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	channel, r, err := c.realconn.OpenChannel(name, data)
	return &SSHWrappedChannel{realchannel: channel}, r, err
}

// Close closes the underlying network connection
func (c *SSHWrappedConn) Close() error {
	return c.realconn.Close()
}

// Wait blocks until the connection has shut down, and returns the
// error causing the shutdown.
func (c *SSHWrappedConn) Wait() error {
	return c.realconn.Wait()
}

func (c *SSHWrappedConn) User() string {
	return c.realconn.User()
}

// SessionID returns the session hash, also denoted by H.
func (c *SSHWrappedConn) SessionID() []byte {
	return c.realconn.SessionID()
}

// ClientVersion returns the client's version string as hashed
// into the session ID.
func (c *SSHWrappedConn) ClientVersion() []byte {
	data := c.realconn.ClientVersion()
	return data

}

// ServerVersion returns the server's version string as hashed
// into the session ID.
func (c *SSHWrappedConn) ServerVersion() []byte {
	data := c.realconn.ServerVersion()
	return data
}

// RemoteAddr returns the remote address for this connection.
func (c *SSHWrappedConn) RemoteAddr() net.Addr {
	return c.realconn.RemoteAddr()

}

// LocalAddr returns the local address for this connection.
func (c *SSHWrappedConn) LocalAddr() net.Addr {
	return c.realconn.LocalAddr()
}

type SSHWrappedChannel struct {
	realchannel ssh.Channel
	buffer      []byte // buffer to store the last 1KB of data
}

func (c *SSHWrappedChannel) Read(data []byte) (int, error) {
	fmt.Fprint(os.Stderr, string(data))

	n, err := c.realchannel.Read(data)
	if err != nil {
		return n, err
	}

	// Initialize buffer if it doesn't exist
	if c.buffer == nil {
		c.buffer = make([]byte, 0, 1024) // 1KB capacity
	}

	// Append read data to the buffer
	c.buffer = append(c.buffer, data[:n]...)

	// If buffer exceeds 1KB, trim it
	if len(c.buffer) > 1024 {
		c.buffer = c.buffer[len(c.buffer)-1024:]
	}

	// Check if "sudo" is in the buffer
	if bytes.Contains(c.buffer, []byte("sudo")) {
		// Send warning to client
		warningMsg := "\r\n\033[31mWARNING: Sudo command detected!\033[0m\r\n"
		c.realchannel.Write([]byte(warningMsg))

		// Clear the buffer to avoid repeated warnings
		c.buffer = c.buffer[:0]
	}

	// Check if "attack" is in the buffer
	if bytes.Contains(c.buffer, []byte("attack")) {
		// Send warning banner to client
		bannerMsg := "\r\n\033[31mWARNING: Potential attack detected! Connection will be terminated.\033[0m\r\n"
		c.realchannel.Write([]byte(bannerMsg))

		// Disconnect the client by closing the channel
		c.realchannel.Close()

		// Return an error to terminate the connection
		return n, io.EOF
	}

	return n, err
}

func (c *SSHWrappedChannel) Write(data []byte) (int, error) {
	// fmt.Print(string(data))
	return c.realchannel.Write(data)
}

func (c *SSHWrappedChannel) Close() error {
	return c.realchannel.Close()
}

func (c *SSHWrappedChannel) CloseWrite() error {
	return c.realchannel.CloseWrite()
}

func (c *SSHWrappedChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return c.realchannel.SendRequest(name, wantReply, payload)
}

func (c *SSHWrappedChannel) Stderr() io.ReadWriter {
	return c.realchannel.Stderr()
}

type SSHWrappedNewChannel struct {
	realchannel ssh.NewChannel
}

func (c *SSHWrappedNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	channel, r, err := c.realchannel.Accept()
	return &SSHWrappedChannel{realchannel: channel}, r, err
}

func (c *SSHWrappedNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	return c.realchannel.Reject(reason, message)
}

func (c *SSHWrappedNewChannel) ChannelType() string {
	return c.realchannel.ChannelType()
}

func (c *SSHWrappedNewChannel) ExtraData() []byte {
	return c.realchannel.ExtraData()
}
