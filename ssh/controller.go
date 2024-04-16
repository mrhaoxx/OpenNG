package ssh

import (
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/tcp"
	ssh "golang.org/x/crypto/ssh"
)

type PasswordCbFn func(ctx *Ctx, password []byte) bool
type PublicKeyCbFn func(ctx *Ctx, key ssh.PublicKey) bool

type ChannelHandler func(*Ctx, ssh.NewChannel)

type controller struct {
	private_keys []ssh.Signer

	banner string

	PasswordCallback  PasswordCbFn
	PublicKeyCallback PublicKeyCbFn

	channelHandlers map[string]ChannelHandler
}

var cur uint64

func (ctl *controller) Handle(c *tcp.Conn) tcp.SerRet {
	serv := ssh.ServerConfig{}
	serv.ServerVersion = "SSH-2.0-OpenNG"
	for _, v := range ctl.private_keys {
		serv.AddHostKey(v)
	}

	ctx := Ctx{
		Id:        atomic.AddUint64(&cur, 1),
		conn:      c,
		starttime: time.Now(),
		auth:      nil,
		User:      "<none>",
	}

	defer func() {

		log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
			"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.auth, ctx.User, ctx.Alt)
	}()

	if ctl.banner != "" {
		serv.BannerCallback = func(conn ssh.ConnMetadata) string {
			b := strings.ReplaceAll(ctl.banner, "%h", conn.RemoteAddr().String())
			b = strings.ReplaceAll(b, "%u", conn.User())
			return b
		}
	}
	if ctl.PasswordCallback != nil {
		serv.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ctx.Meta = conn

			if ctx.User == "<none>" {
				spl := strings.Split(ctx.Meta.User(), "+")

				if len(spl) == 2 {
					ctx.User = spl[0]
					ctx.Alt = spl[1]
				} else {
					ctx.User = spl[0]
				}
			}

			if ctl.PasswordCallback(&ctx, password) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("password rejected")
		}
	}
	if ctl.PublicKeyCallback != nil {
		serv.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ctx.Meta = conn

			if ctx.User == "<none>" {
				spl := strings.Split(ctx.Meta.User(), "+")

				if len(spl) == 2 {
					ctx.User = spl[0]
					ctx.Alt = spl[1]
				} else {
					ctx.User = spl[0]
				}
			}

			if ctl.PublicKeyCallback(&ctx, key) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("public key rejected")
		}
	}

	ctx.sshconn, ctx.nc, ctx.r, ctx.auth = ssh.NewServerConn(c.TopConn(), &serv)

	if ctx.auth != nil {
		return tcp.Close
	}

	// go func() {
	// 	for req := range ctx.r {
	// 		if req.WantReply {
	// 			req.Reply(false, nil)
	// 		}
	// 		log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
	// 			"c"+strconv.FormatUint(ctx.conn.Id, 10), "request", req.Type)
	// 	}
	// }()
	for ch := range ctx.nc {
		// handler := ctl.channelHandlers[ch.ChannelType()]
		// if handler == nil {
		// 	ch.Reject(ssh.UnknownChannelType, "unsupported channel type")
		// 	continue
		// }
		go func() {
			defer func() {
				log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
					"c"+strconv.FormatUint(ctx.conn.Id, 10), ch.ChannelType())

			}()
			// handler(&ctx, ch)
			testing.HandleChannel(&ctx, ch)
		}()
	}

	return tcp.Close
}

func NewSSHController(private_keys []ssh.Signer, banner string, pwdcb PasswordCbFn, pubcb PublicKeyCbFn) *controller {
	testing.privkey = private_keys[0]
	return &controller{
		private_keys:      private_keys,
		banner:            banner,
		PasswordCallback:  pwdcb,
		PublicKeyCallback: pubcb,
	}
}

var testing = proxier{
	hosts: map[string]host{},
}
