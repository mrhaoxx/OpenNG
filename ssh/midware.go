package ssh

import (
	"time"

	"github.com/mrhaoxx/OpenNG/tcp"
	"golang.org/x/crypto/ssh"
)

type Ctx struct {
	//unsync readonly
	Id        uint64
	starttime time.Time

	auth error

	Meta ssh.ConnMetadata

	User string
	Alt  string

	sshconn *ssh.ServerConn

	conn *tcp.Conn

	nc <-chan ssh.NewChannel
	r  <-chan *ssh.Request
}

type midware struct {
}
