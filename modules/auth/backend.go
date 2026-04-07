package auth

import (
	"github.com/mrhaoxx/OpenNG/modules/ngssh"

	gossh "golang.org/x/crypto/ssh"
)

type PolicyBackend interface {
	CheckPassword(username string, password string) bool
	ExistsUser(username string) bool
}

type SSHKeyChecker interface {
	CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) bool
}

type ForwardProxyAuthorizer interface {
	AllowForwardProxy(username string) bool
}

type ClientCertChecker interface {
	CheckClientCert(fingerprint string) (username string, ok bool)
}

type backendGroup []PolicyBackend

func (b backendGroup) CheckPassword(username string, password string) (bool, int) {
	for i, backend := range b {
		if backend.CheckPassword(username, password) {
			return true, i
		}
	}
	return false, -1
}

func (b backendGroup) CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) (bool, int) {
	for i, backend := range b {
		if checker, ok := backend.(SSHKeyChecker); ok {
			if checker.CheckSSHKey(ctx, key) {
				return true, i
			}
		}
	}
	return false, -1
}

func (b backendGroup) AllowForwardProxy(username string) (bool, int) {
	for i, backend := range b {
		if auth, ok := backend.(ForwardProxyAuthorizer); ok {
			if auth.AllowForwardProxy(username) {
				return true, i
			}
		}
	}
	return false, -1
}

func (b backendGroup) CheckClientCert(fingerprint string) (username string, ok bool, src int) {
	for i, backend := range b {
		if checker, ok := backend.(ClientCertChecker); ok {
			if username, ok := checker.CheckClientCert(fingerprint); ok {
				return username, true, i
			}
		}
	}
	return "", false, -1
}
