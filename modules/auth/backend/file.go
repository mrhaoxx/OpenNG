package auth

import (
	"reflect"
	"sync"
	"time"

	"github.com/mrhaoxx/OpenNG/modules/ssh"
	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
)

type user struct {
	name                string
	passwordHash        string
	webAuthn            []string
	allow_forward_proxy bool
	sshkeys             []gossh.PublicKey
	allowsshpwd         bool

	passwordmap sync.Map
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (usr *user) checkpwd(passwd string) bool {
	if usr == nil {
		goto _false
	}

	if _, ok := usr.passwordmap.Load(passwd); ok {
		return true
	}

	if CheckPasswordHash(passwd, usr.passwordHash) {
		usr.passwordmap.Store(passwd, struct{}{})
		return true
	}

_false:
	time.Sleep(time.Millisecond * 600)

	return false
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

func (mgr *fileBackend) ExistsUser(username string) bool {
	_, ok := mgr.usrs[username]
	return ok
}
