package ssh

import (
	"encoding/base64"
	"io"
	"strconv"
	"strings"
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

type Host struct {
	Name string

	Addr string

	Pubkey ssh.PublicKey
}

type Proxier struct {
	Hosts map[string]Host

	Privkey []ssh.Signer
}

func (p *Proxier) HandleConn(ctx *Ctx) {

	h, ok := p.Hosts[strings.ToLower(ctx.Alt)]
	if !ok {

		ctx.Error("unknown host\r\n")

		return
	}

	cfg := ssh.ClientConfig{
		User:          ctx.User,
		ClientVersion: string("SSH-2.0-OpenNG"),
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(p.Privkey...)},
	}
	if h.Pubkey != nil {
		cfg.HostKeyCallback = ssh.FixedHostKey(h.Pubkey)
	} else {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	remote, err := ssh.Dial("tcp", h.Addr, &cfg)
	if err != nil {
		var k string
		for _, key := range p.Privkey {
			key_ := string(ssh.MarshalAuthorizedKey(key.PublicKey()))
			k += "    " + key_[:len(key_)-1] + " OpenNG Server Access\r\n"
		}

		ctx.Error("* Failed to connect to remote host: " + err.Error() + "\r\n" +
			"* If this is an authentication issue, please add one of these public keys\r\n" +
			k +
			"* to user " + ctx.User + " authorized_keys file in the remote host.\r\n")
		return
	}
	defer remote.Close()
	go func() {
		remote.Wait()

		ctx.sshconn.Close()
	}()

	go func() {
		for nc := range remote.HandleChannelOpen("forwarded-tcpip") {
			chn := atomic.AddUint64(&ctx.chn, 1) - 1
			go func() {
				defer func() {
					log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
						"s"+strconv.FormatUint(ctx.Id, 10), nc.ChannelType(), base64.StdEncoding.EncodeToString(nc.ExtraData()))
				}()
				p.HandleChannel(ctx, nc, ctx.sshconn, chn)
			}()
		}
	}()

	go func() {
		for nc := range remote.HandleChannelOpen("direct-tcpip") {
			chn := atomic.AddUint64(&ctx.chn, 1) - 1
			go func() {
				defer func() {
					log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
						"s"+strconv.FormatUint(ctx.Id, 10), nc.ChannelType(), base64.StdEncoding.EncodeToString(nc.ExtraData()))
				}()
				p.HandleChannel(ctx, nc, ctx.sshconn, chn)
			}()
		}
	}()

	go func() {
		for nc := range remote.HandleChannelOpen("x11") {
			chn := atomic.AddUint64(&ctx.chn, 1) - 1
			go func() {
				defer func() {
					log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
						"s"+strconv.FormatUint(ctx.Id, 10), nc.ChannelType(), base64.StdEncoding.EncodeToString(nc.ExtraData()))
				}()
				p.HandleChannel(ctx, nc, ctx.sshconn, chn)
			}()
		}
	}()

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
func (p *Proxier) HandleChannel(ctx *Ctx, nc ssh.NewChannel, remote ssh.Conn, chn uint64) {

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

	go io.Copy(c.Stderr(), _c.Stderr())
	go io.Copy(_c.Stderr(), c.Stderr())

	go func() {
		io.Copy(c, _c)
		c.CloseWrite()
	}()

	go func() {
		for a := range r {
			_1, _ := _c.SendRequest(a.Type, a.WantReply, a.Payload)
			a.Reply(_1, nil)
			if a.Type == "exit-status" || a.Type == "exit-signal" {
				_c.Close()
			}
		}
	}()
	for a := range _r {
		_1, _ := c.SendRequest(a.Type, a.WantReply, a.Payload)
		a.Reply(_1, nil)
		if a.Type == "exit-status" || a.Type == "exit-signal" {
			c.Close()
		}
	}
}
