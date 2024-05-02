package auth

import (
	"reflect"
	"sync"
	"time"

	"github.com/mrhaoxx/OpenNG/ssh"
	"github.com/mrhaoxx/OpenNG/utils"
	gossh "golang.org/x/crypto/ssh"
)

type user struct {
	name                string
	passwordHash        string
	allow_forward_proxy bool
	sshkeys             []gossh.PublicKey
	allowsshpwd         bool

	passwordmap sync.Map
}

func (usr *user) checkpwd(passwd string) bool {
	if usr == nil {
		goto _false
	}

	if _, ok := usr.passwordmap.Load(passwd); ok {
		return true
	}

	if utils.CheckPasswordHash(passwd, usr.passwordHash) {
		usr.passwordmap.Store(passwd, struct{}{})
		return true
	}

_false:
	time.Sleep(time.Millisecond * 600)

	return false
}

type policy struct {
	name string

	allowance bool

	users map[string]bool

	hosts utils.GroupRegexp
	hup   *utils.BufferedLookup

	paths utils.GroupRegexp
}

// 0 -> next;1 -> refuse;2 -> accept
func (p *policy) check(username string, path string) uint8 {
	if p.users[""] || p.users[username] {
		if p.paths.MatchString(path) {
			if p.allowance {
				return 2
			} else {
				return 1
			}
		}
	}
	return 0
}

type fileBackend struct {
	usrs map[string]*user
}

func (mgr *fileBackend) CheckSSHKey(ctx *ssh.Ctx, pubkey gossh.PublicKey) bool {
	usr, ok := mgr.usrs[ctx.User]
	if !ok {
		return false
	}
	for _, key := range usr.sshkeys {
		if pubkey.Type() == key.Type() && reflect.DeepEqual(pubkey.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

func (mgr *fileBackend) CheckPassword(username string, password string) bool {
	usr, ok := mgr.usrs[username]
	if !ok {
		return false
	}
	return usr.checkpwd(password)
}

func (mgr *fileBackend) SetUser(username string, passwordhash string, allow_forward_proxy bool, sshkeys []gossh.PublicKey, allowsshpwd bool) {
	mgr.usrs[username] = &user{
		name:                username,
		passwordHash:        passwordhash,
		allow_forward_proxy: allow_forward_proxy,
		sshkeys:             sshkeys,
		allowsshpwd:         allowsshpwd,
	}
}

func (mgr *fileBackend) AllowForwardProxy(username string) bool {
	usr, ok := mgr.usrs[username]
	if !ok {
		return false
	}
	return usr.allow_forward_proxy
}

func NewFileBackend() *fileBackend {
	return &fileBackend{
		usrs: make(map[string]*user),
	}
}
