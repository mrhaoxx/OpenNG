package ssh

import (
	"encoding/base64"
	"io"
	"strconv"
	"sync/atomic"
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

func (p *proxier) HandleConn(ctx *Ctx) {

	h, ok := p.hosts[ctx.Alt]
	if !ok {

		ctx.Error("unknown host\r\n")

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
		k := ssh.MarshalAuthorizedKey(p.privkey.PublicKey())

		ctx.Error("* Failed to connect to remote host: " + err.Error() + "\r\n" +
			"* Please Add \r\n	" +
			string(k[:len(k)-1]) + " OpenNG Server Access\r\n " +
			"to user " + ctx.User + " in the remote host's authorized_keys file.\r\n")
		return
	}

	go func() {
		for req := range ctx.r {
			_1, _2, _ := remote.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(_1, _2)
			}
			log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
				"c"+strconv.FormatUint(ctx.conn.Id, 10), req.Type, base64.StdEncoding.EncodeToString(req.Payload))
		}
	}()

	for ch := range ctx.nc {
		chn := atomic.AddUint64(&ctx.chn, 1) - 1
		go func() {
			defer func() {
				log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
					"s"+strconv.FormatUint(ctx.Id, 10), ch.ChannelType(), base64.StdEncoding.EncodeToString(ch.ExtraData()))
			}()
			p.HandleChannel(ctx, ch, remote, chn)
		}()
	}

}
func (p *proxier) HandleChannel(ctx *Ctx, nc ssh.NewChannel, remote *ssh.Client, chn uint64) {

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
		io.Copy(_c, c)
		_c.CloseWrite()
	}()

	go func() {
		io.Copy(c, _c)
		c.CloseWrite()
	}()

	for {
		select {
		case a, ok := <-r:
			if !ok {
				goto _fin
			}

			_1, _ := _c.SendRequest(a.Type, a.WantReply, a.Payload)

			a.Reply(_1, nil)

			if a.Type == "exit-status" {
				_c.Close()
			}

			// log.Println("ssh", "proxy", "requestA", err, a.Type, a.WantReply, string(a.Payload))
		case a, ok := <-_r:
			if !ok {
				goto _fin
			}

			_1, _ := c.SendRequest(a.Type, a.WantReply, a.Payload)
			a.Reply(_1, nil)

			if a.Type == "exit-status" {
				c.Close()
			}
			// log.Println("ssh", "proxy", "requestB", err, a.Type, a.WantReply, string(a.Payload))

		}
		// log.Println("ssh", "proxy", "loop", err)

	}
_fin:
}
