package socks

import (
	"strconv"
	"sync/atomic"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/things-go/go-socks5"
)

type socks5Server struct {
	s *socks5.Server

	count uint64
}

type Socks5AuthFn func(username string, password string, userAddr string) bool

type socks5Auth struct {
	Socks5AuthFn
}

func (auth *socks5Auth) Valid(username string, password string, userAddr string) bool {
	return auth.Socks5AuthFn(username, password, userAddr)
}

func NewSocks5Server(auther Socks5AuthFn) *socks5Server {
	if auther == nil {
		return &socks5Server{socks5.NewServer(), 0}
	} else {
		return &socks5Server{socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{
			socks5.UserPassAuthenticator{Credentials: &socks5Auth{auther}},
		})), 0}
	}
}

func (server *socks5Server) Handle(c *tcp.Conn) tcp.SerRet {

	s := server.s.ServeConn(c.TopConn())

	log.Println("ss"+strconv.FormatUint(atomic.AddUint64(&server.count, 1), 10), c.TopConn().RemoteAddr(), s)

	return tcp.Close
}
