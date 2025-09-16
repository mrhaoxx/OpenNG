package ssh

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/utils"
	ssh "golang.org/x/crypto/ssh"

	zlog "github.com/rs/zerolog/log"
)

type Ctx struct {
	//unsync readonly
	Id        uint64
	starttime time.Time

	chn uint64

	auth error

	Meta ssh.ConnMetadata

	username string

	User string
	Alt  string

	sshconn *ssh.ServerConn

	conn *tcp.Conn

	nc <-chan ssh.NewChannel
	r  <-chan *ssh.Request
}

func (ctx *Ctx) initUserAlt() {

	if ctx.username == "<none>" {
		ctx.username = ctx.Meta.User()

		spl := strings.Split(ctx.username, "+")

		if len(spl) >= 2 {
			ctx.User = spl[0]
			ctx.Alt = strings.Join(spl[1:], "+")
		} else {
			ctx.User = spl[0]
		}
	}

}

func (ctx *Ctx) Error(err_msg string) {
	for ch := range ctx.nc {
		n, _, _ := ch.Accept()
		n.Stderr().Write([]byte(err_msg + "\r\n"))
		break
	}
	ctx.sshconn.Close()
}

type PasswordCbFn func(ctx *Ctx, password []byte) bool
type PublicKeyCbFn func(ctx *Ctx, key ssh.PublicKey) bool
type ConnHandler interface {
	HandleConn(*Ctx)
}

type srv struct {
	hdr      ConnHandler
	matchalt utils.GroupRegexp
}

type Midware struct {
	private_keys []ssh.Signer

	banner     string
	rnd_quotes []string

	PasswordCallback  PasswordCbFn
	PublicKeyCallback PublicKeyCbFn

	current        []srv
	bufferedLookup *utils.BufferedLookup[ConnHandler]

	basecfg ssh.ServerConfig
}

var cur uint64

func (ctl *Midware) Handle(c *tcp.Conn) tcp.SerRet {
	serv := ctl.basecfg

	ctx := Ctx{
		Id:        atomic.AddUint64(&cur, 1),
		conn:      c,
		starttime: time.Now(),
		auth:      nil,
		username:  "<none>",
	}

	path := ""

	defer func() {
		if ctx.sshconn != nil {
			ctx.sshconn.Close()
		}

		// log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
		// 	"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.username, path)
		zlog.Info().
			Str("type", "ssh/conn").
			Uint64("id", ctx.Id).
			Str("remote", ctx.conn.Addr().String()).
			Dur("duration", time.Since(ctx.starttime)).
			Str("username", ctx.username).
			Str("conn", ctx.conn.Id).
			Str("routine", path).
			Msg("")
	}()

	if ctl.banner != "" {
		serv.BannerCallback = func(conn ssh.ConnMetadata) string {
			b := strings.ReplaceAll(ctl.banner, "%h", conn.RemoteAddr().String())
			b = strings.ReplaceAll(b, "%u", conn.User())
			b = strings.ReplaceAll(b, "%t", ctx.starttime.Format(time.RFC1123Z))

			if len(ctl.rnd_quotes) > 0 {
				b += "%%% " + ctl.rnd_quotes[ctx.starttime.UnixMilli()%int64(len(ctl.rnd_quotes))] + "\n"
			}
			return b
		}
	}

	if ctl.PasswordCallback != nil {
		serv.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			path += "@pwd "

			ctx.Meta = conn

			ctx.initUserAlt()

			if ctl.PasswordCallback(&ctx, password) {
				// log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
				// 	"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.username, "+", "ssh-pwd", "******")
				zlog.Info().
					Str("type", "ssh/auth").
					Uint64("id", ctx.Id).
					Str("remote", ctx.conn.Addr().String()).
					Dur("duration", time.Since(ctx.starttime)).
					Str("username", ctx.username).
					Str("conn", ctx.conn.Id).
					Str("method", "ssh-pwd").
					Str("status", "passed").
					Msg("")
				return &ssh.Permissions{}, nil
			}

			// log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
			// 	"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.username, "-", "ssh-pwd", strconv.Quote(string(password)))

			zlog.Info().
				Str("type", "ssh/auth").
				Uint64("id", ctx.Id).
				Str("remote", ctx.conn.Addr().String()).
				Dur("duration", time.Since(ctx.starttime)).
				Str("username", ctx.username).
				Str("conn", ctx.conn.Id).
				Str("method", "ssh-pwd").
				Str("password", string(password)).
				Str("status", "failed").
				Msg("")
			return nil, errors.New("password rejected")
		}
	}
	if ctl.PublicKeyCallback != nil {
		serv.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			path += "@key "

			ctx.Meta = conn

			ctx.initUserAlt()

			if ctl.PublicKeyCallback(&ctx, key) {
				// log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
				// 	"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.username, "+", string(MarshalAuthorizedKey(key)))
				zlog.Info().
					Str("type", "ssh/auth").
					Uint64("id", ctx.Id).
					Str("remote", ctx.conn.Addr().String()).
					Dur("duration", time.Since(ctx.starttime)).
					Str("username", ctx.username).
					Str("conn", ctx.conn.Id).
					Str("method", key.Type()).
					Str("status", "passed").
					Str("key", string(MarshalAuthorizedKey(key))).
					Msg("")
				return &ssh.Permissions{}, nil
			}

			// log.Println("s"+strconv.FormatUint(ctx.Id, 10), ctx.conn.Addr().String(), time.Since(ctx.starttime).Round(1*time.Microsecond),
			// 	"c"+strconv.FormatUint(ctx.conn.Id, 10), ctx.username, "-", string(MarshalAuthorizedKey(key)))
			zlog.Info().
				Str("type", "ssh/auth").
				Uint64("id", ctx.Id).
				Str("remote", ctx.conn.Addr().String()).
				Dur("duration", time.Since(ctx.starttime)).
				Str("username", ctx.username).
				Str("conn", ctx.conn.Id).
				Str("method", key.Type()).
				Str("key", string(MarshalAuthorizedKey(key))).
				Str("status", "failed").
				Msg("")

			return nil, errors.New("public key rejected")
		}
	}

	ctx.sshconn, ctx.nc, ctx.r, ctx.auth = ssh.NewServerConn(c.TopConn(), &serv)

	if ctx.auth != nil {
		path += "!"
		return tcp.Close
	}

	path += "+" + ctx.User + " "

	f := ctl.bufferedLookup.Lookup(ctx.Alt)

	if f == nil {
		ctx.Error("SSH/2.0 418 I'm a teapot")
		path += "#"
		return tcp.Close
	}

	path += "."

	f.HandleConn(&ctx)

	return tcp.Close
}

func (c *Midware) AddHandler(h ConnHandler, alt utils.GroupRegexp) {
	c.current = append(c.current, srv{hdr: h, matchalt: alt})
}

func NewSSHController(private_keys []ssh.Signer, banner string, quotes []string, pwdcb PasswordCbFn, pubcb PublicKeyCbFn) *Midware {
	Midware := Midware{
		private_keys:      private_keys,
		banner:            banner,
		PasswordCallback:  pwdcb,
		PublicKeyCallback: pubcb,
		rnd_quotes:        quotes,
	}

	basecfg := ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenNG",
	}

	for _, v := range private_keys {
		basecfg.AddHostKey(v)
	}

	Midware.basecfg = basecfg

	Midware.bufferedLookup = utils.NewBufferedLookup(func(s string) ConnHandler {
		for _, t := range Midware.current {
			if t.matchalt.MatchString(s) {
				return t.hdr
			}
		}
		return nil
	})
	return &Midware
}

func MarshalAuthorizedKey(key ssh.PublicKey) []byte {
	b := &bytes.Buffer{}
	b.WriteString(key.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(key.Marshal())
	e.Close()
	return b.Bytes()
}
