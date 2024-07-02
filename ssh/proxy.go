package ssh

import (
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/utils"
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

	User        string
	IdentityKey ssh.Signer
	Password    string

	AllowedUsers utils.GroupRegexp
}

type proxier struct {
	Hosts map[string]Host

	Privkey []ssh.Signer

	keyBanner string

	AllowDnsQuery bool
}

func NewSSHProxier(hosts map[string]Host, keys []ssh.Signer) *proxier {

	var k string
	for _, key := range keys {
		key_ := string(ssh.MarshalAuthorizedKey(key.PublicKey()))
		k += "    " + key_[:len(key_)-1] + " OpenNG Server Access\r\n"
	}
	p := &proxier{
		Hosts:     hosts,
		Privkey:   keys,
		keyBanner: k,
	}
	return p
}

func (p *proxier) HandleConn(ctx *Ctx) {
	HostName := ctx.Alt

	h, ok := p.Hosts[HostName]
	if !ok {

		ctx.Error("* Unknown host " + strconv.Quote(ctx.Alt) + "\r\n")

		return
	}

	if h.AllowedUsers != nil && !h.AllowedUsers.MatchString(ctx.User) {
		return
	}

	var auth_method []ssh.AuthMethod
	if h.IdentityKey != nil {
		auth_method = []ssh.AuthMethod{ssh.PublicKeys(h.IdentityKey)}
	} else if h.Password != "" {
		auth_method = []ssh.AuthMethod{ssh.Password(h.Password)}
	} else {
		auth_method = []ssh.AuthMethod{ssh.PublicKeys(p.Privkey...)}
	}

	var user string
	if h.User != "" {
		user = h.User
	} else {
		user = ctx.User
	}

	cfg := ssh.ClientConfig{
		User:          user,
		ClientVersion: string("SSH-2.0-OpenNG"),
		Auth:          auth_method,
		Timeout:       time.Second * 3,
	}

	if h.Pubkey != nil {
		cfg.HostKeyCallback = ssh.FixedHostKey(h.Pubkey)
	} else {
		cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	remote_conn, err := net.DialTimeout("tcp", h.Addr, cfg.Timeout)

	if err != nil {
		ctx.Error("* Failed to connect to remote host: " + err.Error() + "\r\n")
		return
	}

	remote, chans, reqs, err := ssh.NewClientConn(remote_conn, h.Addr, &cfg)

	if err != nil {
		ctx.Error("* Failed to connect to remote host: " + err.Error() + "\r\n" +
			"* If this is an authentication issue, please add one of these public keys\r\n" +
			p.keyBanner +
			"* to user " + ctx.User + " authorized_keys file in the remote host.\r\n")
		return
	}

	go func() {
		for nc := range chans {
			chn := atomic.AddUint64(&ctx.chn, 1) - 1
			go func() {
				defer func() {
					log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
						"s"+strconv.FormatUint(ctx.Id, 10), "<", nc.ChannelType(), hex.EncodeToString(nc.ExtraData()))
				}()
				p.HandleChannel(ctx, nc, ctx.sshconn, chn)
			}()
		}

	}()

	go func() {
		for ch := range ctx.nc {
			chn := atomic.AddUint64(&ctx.chn, 1) - 1
			go func() {
				defer func() {
					log.Println("n"+strconv.FormatUint(chn, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
						"s"+strconv.FormatUint(ctx.Id, 10), ">", ch.ChannelType(), hex.EncodeToString(ch.ExtraData()))
				}()
				p.HandleChannel(ctx, ch, remote, chn)
			}()
		}
	}()

	go func() {
		defer ctx.sshconn.Close()

		for req := range reqs {
			switch req.Type {
			case "hostkeys-00@openssh.com": // Unsupported OpenSSH extension
				continue
			}
			_1, _2, _ := ctx.sshconn.SendRequest(req.Type, req.WantReply, req.Payload)
			req.Reply(_1, _2)

			log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
				"c"+strconv.FormatUint(ctx.conn.Id, 10), "<", req.Type, hex.EncodeToString(req.Payload))
		}
	}()

	defer remote.Close()

	for req := range ctx.r {
		_1, _2, _ := remote.SendRequest(req.Type, req.WantReply, req.Payload)
		req.Reply(_1, _2)

		log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
			"c"+strconv.FormatUint(ctx.conn.Id, 10), ">", req.Type, hex.EncodeToString(req.Payload))
	}

}
func (p *proxier) HandleChannel(ctx *Ctx, nc ssh.NewChannel, remote ssh.Conn, chn uint64) {

	_c, _r, err := remote.OpenChannel(nc.ChannelType(), nc.ExtraData())

	if err != nil {
		// log.Println(err)
		e, ok := err.(*ssh.OpenChannelError)
		if !ok {
			nc.Reject(ssh.Prohibited, err.Error())
			return
		}
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
