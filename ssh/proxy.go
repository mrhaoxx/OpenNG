package ssh

import (
	"io"
	"strconv"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"golang.org/x/crypto/ssh"
)

const (
	AuthNone uint8 = iota
	AuthPassword
	AuthPublicKey
	AuthKeyboardInteractive
)

type host struct {
	name string

	addr string

	auth uint8

	pubkey ssh.PublicKey
}

type proxier struct {
	hosts map[string]host

	privkey ssh.Signer
}

func (p *proxier) HandleChannel(ctx *Ctx, nc ssh.NewChannel) {

	defer func() {
		log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
			"c"+strconv.FormatUint(ctx.conn.Id, 10), nc.ChannelType())
	}()
	h, ok := p.hosts[ctx.Alt]
	if !ok {
		nc.Reject(ssh.ConnectionFailed, "unknown host")
		return
	}

	cfg := ssh.ClientConfig{
		User:            ctx.User,
		ClientVersion:   string("SSH-2.0-OpenNG"),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(p.privkey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	remote, err := ssh.Dial("tcp", h.addr, &cfg)
	if err != nil {
		c, _, _ := nc.Accept()
		k := ssh.MarshalAuthorizedKey(p.privkey.PublicKey())
		c.Write([]byte("\n* Please Add \n" + string(k[:len(k)-1]) + " OpenNG Server Access\n to user " + ctx.User + " in the remote host's authorized_keys file.\n\n"))
		// nc.Reject(ssh.ConnectionFailed, "\n\n* Please Add "+string(k[:len(k)-1])+" to user "+ctx.User+" in the remote host's authorized_keys file.")
		c.Close()
		return
	}

	_c, _r, err := remote.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		e := err.(*ssh.OpenChannelError)
		nc.Reject(e.Reason, e.Message)
		return
	}

	c, r, err := nc.Accept()

	if err != nil {
		panic("accept failed")
	}
	go func() {
		for req := range ctx.r {
			_1, _2, _ := remote.SendRequest(req.Type, req.WantReply, req.Payload)
			req.Reply(_1, _2)
			log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
				"c"+strconv.FormatUint(ctx.conn.Id, 10), "request", req.Type)
		}
		log.Println("end")
	}()
	go func() {
		// for {
		// 	buf := make([]byte, 8192)
		// 	n, err := c.Read(buf)
		// 	if err != nil {
		// 		log.Println("ssh", "proxy", "readB", err)
		// 		break
		// 	}
		// 	_c.Write(buf[:n])
		// 	// log.Println("ssh", "proxy", "writeA", buf[:n])
		// }
		io.Copy(_c, c)
		_c.CloseWrite()

		// _c.CloseWrite()
	}()

	go func() {
		// for {
		// 	buf := make([]byte, 8192)
		// 	n, err := _c.Read(buf)
		// 	if err != nil {
		// 		log.Println("ssh", "proxy", "readA", err)
		// 		break
		// 	}
		// 	c.Write(buf[:n])
		// 	// log.Println("ssh", "proxy", "writeB", buf[:n])
		// }
		io.Copy(c, _c)
		c.CloseWrite()

	}()

	// defer c.Close()
	// defer _c.Close()

	for {
		select {
		case a, ok := <-r:
			if !ok {
				goto _fin
			}

			_1, _ := _c.SendRequest(a.Type, a.WantReply, a.Payload)
			a.Reply(_1, nil)
			log.Println("ssh", "proxy", "requestA", err, a.Type, a.WantReply, string(a.Payload))
		case a, ok := <-_r:
			if !ok {
				goto _fin
			}

			_1, _ := c.SendRequest(a.Type, a.WantReply, a.Payload)
			a.Reply(_1, nil)

			if a.Type == "exit-status" {
				c.Close()
			}
			log.Println("ssh", "proxy", "requestB", err, a.Type, a.WantReply, string(a.Payload))

		}
		log.Println("ssh", "proxy", "loop", err)

	}
_fin:
}
