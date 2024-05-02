package auth

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
	"github.com/mrhaoxx/OpenNG/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type ldapBackend struct {
	url        string
	searchBase string

	bindDN string
	bindPW string

	ldapQueryConnPool sync.Pool
}

func (backend *ldapBackend) tryGetQueryConn() *ldap.Conn {
	conn, ok := backend.ldapQueryConnPool.Get().(*ldap.Conn)
	if !ok {
		return nil
	}
	for conn.IsClosing() {
		if !ok {
			return nil
		}

		conn, ok = backend.ldapQueryConnPool.Get().(*ldap.Conn)
	}

	return conn
}

func (backend *ldapBackend) CheckPassword(username string, password string) bool {

	conn := backend.tryGetQueryConn()
	defer backend.ldapQueryConnPool.Put(conn)

	searchRequest := ldap.NewSearchRequest(
		backend.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(uid="+username+"))",
		[]string{"dn"},
		nil,
	)
	if result, err := conn.Search(searchRequest); err == nil {
		if len(result.Entries) != 1 {
			return false
		}

		try, err := ldap.DialURL(backend.url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			return false
		}
		defer try.Close()

		return try.Bind(result.Entries[0].DN, password) == nil

	}
	return false
}

func (backend *ldapBackend) CheckSSHKey(ctx *ssh.Ctx, pubkey gossh.PublicKey) bool {

	if strings.ContainsAny(ctx.User, "\" ',=+<>#:;\\()") {
		return false
	}

	conn := backend.tryGetQueryConn()
	defer backend.ldapQueryConnPool.Put(conn)

	searchRequest := ldap.NewSearchRequest(
		backend.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(uid="+ctx.User+"))",
		[]string{"sshPublicKey"},
		nil,
	)
	if result, err := conn.Search(searchRequest); err == nil {
		if len(result.Entries) != 1 {
			return false
		}

		for _, attr := range result.Entries[0].Attributes {
			if attr.Name != "sshPublicKey" {
				continue
			}

			for _, val := range attr.Values {
				got, _, _, _, err := gossh.ParseAuthorizedKey([]byte(val))
				if err != nil {
					continue
				}
				if pubkey.Type() == got.Type() && reflect.DeepEqual(pubkey.Marshal(), got.Marshal()) {
					return true
				}
			}
		}
	}
	return false
}

func (mgr *ldapBackend) AllowForwardProxy(username string) bool {
	return false
}

func NewLDAPBackend(url, searchBase, bindDN, bindPW string) *ldapBackend {

	back := &ldapBackend{
		url:        url,
		searchBase: searchBase,
		bindDN:     bindDN,
		bindPW:     bindPW,
	}

	back.ldapQueryConnPool.New = func() interface{} {
		conn, err := ldap.DialURL(back.url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			panic(err)
		}
		err = conn.Bind(back.bindDN, back.bindPW)
		if err != nil {
			panic(err)
		}
		fmt.Println("LDAP connection established")
		return conn
	}

	return back
}
