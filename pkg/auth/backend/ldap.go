package auth

import (
	"crypto/tls"
	"reflect"
	"sync"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/mrhaoxx/OpenNG/pkg/ngssh"
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
	// only allow a-z A-Z 0-9 _ - . @
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-' && r != '.' && r != '@' {
			return false
		}
	}

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

func (backend *ldapBackend) CheckSSHKey(ctx *ngssh.Ctx, pubkey gossh.PublicKey) bool {
	// only allow a-z A-Z 0-9 _ - . @
	for _, r := range ctx.User {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-' && r != '.' && r != '@' {
			return false
		}
	}

	keys, err := backend.searchUserSSHPubkey(ctx.User)

	if err != nil {
		return false
	}

	for _, key := range keys {
		out, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			continue
		}
		if out.Type() == pubkey.Type() && reflect.DeepEqual(out.Marshal(), pubkey.Marshal()) {
			return true
		}
	}

	return false
}

func (backend *ldapBackend) searchUserSSHPubkey(username string) (ret []string, err error) {

	conn := backend.tryGetQueryConn()
	defer backend.ldapQueryConnPool.Put(conn)

	sr, err := conn.Search(ldap.NewSearchRequest(
		backend.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(uid="+username+"))",
		[]string{"sshPublicKey", "memberUid"},
		nil,
	))

	if err != nil {
		return
	}

	var memberUidsOfUser []string

	for _, entry := range sr.Entries {
		for _, attr := range entry.Attributes {
			if attr.Name == "sshPublicKey" {
				ret = append(ret, attr.Values...)
			} else if attr.Name == "memberUid" {
				memberUidsOfUser = append(memberUidsOfUser, attr.Values...)
			}
		}
	}

	var to_join_users string
	for _, uid := range memberUidsOfUser {
		to_join_users += "(uid=" + uid + ")"
	}

	sr, err = conn.Search(ldap.NewSearchRequest(
		backend.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(&(objectClass=posixGroup)(|(memberUid="+username+")(memberUid=ALL)))(&(objectClass=posixAccount)(|"+to_join_users+")))",
		[]string{"sshPublicKey"},
		nil,
	))

	if err != nil {
		return
	}

	for _, entry := range sr.Entries {
		for _, attr := range entry.Attributes {
			ret = append(ret, attr.Values...)
		}
	}

	return

}

func (mgr *ldapBackend) AllowForwardProxy(username string) bool {
	return false
}

func NewLDAPBackend(url *ngnet.URL, searchBase, bindDN, bindPW string) *ldapBackend {

	back := &ldapBackend{
		url:        url.String(),
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
		// fmt.Println("LDAP connection established")
		return conn
	}

	return back
}

func (mgr *ldapBackend) ExistsUser(username string) bool {
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_' && r != '-' && r != '.' && r != '@' {
			return false
		}
	}

	conn := mgr.tryGetQueryConn()
	defer mgr.ldapQueryConnPool.Put(conn)

	searchRequest := ldap.NewSearchRequest(
		mgr.searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(uid="+username+"))",
		[]string{"dn"},
		nil,
	)
	if result, err := conn.Search(searchRequest); err == nil {
		return len(result.Entries) == 1
	}
	return false
}
