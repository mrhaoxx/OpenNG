package auth

import (
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stdhttp "net/http"

	"github.com/mrhaoxx/OpenNG/dns"
	http "github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/ssh"
	utils "github.com/mrhaoxx/OpenNG/utils"

	gossh "golang.org/x/crypto/ssh"
)

type session struct {
	lastseen time.Time
	active   uint64

	muS      sync.Mutex
	username string
	src      int
}

func (u *session) id() string {
	return "[" + strconv.Itoa(u.src) + "]" + u.username
}

func (u *session) renew() {
	u.muS.Lock()
	u.lastseen = time.Now()
	u.muS.Unlock()
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
		if p.paths == nil || p.paths.MatchString(path) {
			if p.allowance {
				return 2
			} else {
				return 1
			}
		}
	}
	return 0
}

type policyBaseAuth struct {
	policies        []*policy
	policyLookupBuf *utils.BufferedLookup

	backends backendGroup

	sessions  map[string]*session
	muSession sync.RWMutex
}

func (p *policyBaseAuth) at(session string) *session {
	p.muSession.RLock()
	defer p.muSession.RUnlock()
	return p.sessions[session]
}

type PolicyBackend interface {
	CheckPassword(username string, password string) bool
	CheckSSHKey(ctx *ssh.Ctx, key gossh.PublicKey) bool
	AllowForwardProxy(username string) bool
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

func (b backendGroup) CheckSSHKey(ctx *ssh.Ctx, key gossh.PublicKey) (bool, int) {
	for i, backend := range b {
		if backend.CheckSSHKey(ctx, key) {
			return true, i
		}
	}
	return false, -1
}

func (b backendGroup) AllowForwardProxy(username string) (bool, int) {
	for i, backend := range b {
		if backend.AllowForwardProxy(username) {
			return true, i
		}
	}
	return false, -1
}

func NewPBAuth() *policyBaseAuth {
	po := &policyBaseAuth{
		sessions: map[string]*session{},
	}

	po.policyLookupBuf = utils.NewBufferedLookup(func(s string) interface{} {
		var r []*policy = nil
		for _, p := range po.policies {
			if p.hosts == nil || p.hosts.MatchString(s) {
				r = append(r, p)
			}
		}
		return r
	})

	go func() {
		for range time.Tick(time.Minute * 10) {
			po.Clean()
		}
	}()
	return po

}

func (mgr *policyBaseAuth) HandleAuth(ctx *http.HttpCtx) AuthRet {
	// First Lets get user info
	var token = ctx.RemoveCookie(verfiyCookieKey)

	var session *session
	var user string

	if token != "" {
		session = mgr.at(token)

		if session != nil {
			user = session.username
			session.renew()
		}
	}

	switch mgr.determine(ctx.Req.Host, ctx.Req.URL.Path, user) {
	case 2:
		if session != nil {
			atomic.AddUint64(&session.active, uint64(1))

			ctx.RegCloseHandle(func(*http.HttpCtx) {
				atomic.AddUint64(&session.active, ^uint64(0))
			})
		}

		return Accept
	case 0:
		return Continue // no hit
	case 1:
		url := http.PrefixNg + PrefixAuth + PrefixAuthPolicy + "/login?r=" + base64.URLEncoding.EncodeToString([]byte(ctx.Req.RequestURI))
		ctx.Redirect(url, http.StatusFound) //auth required
	}

	return Deny

}

func needAuth(ctx *http.HttpCtx) {
	ctx.Resp.Header().Set("Proxy-Authenticate", "Basic realm=\""+utils.ServerSign+"\"")
	ctx.Resp.WriteHeader(http.StatusProxyAuthRequired)
}

func (l *policyBaseAuth) HandleProxy(ctx *http.HttpCtx) http.Ret {
	hdr := ctx.Req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		needAuth(ctx)
		return http.RequestEnd
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		needAuth(ctx)
		return http.RequestEnd
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		needAuth(ctx)
		return http.RequestEnd
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		needAuth(ctx)
		return http.RequestEnd
	}

	login := pair[0]
	password := pair[1]

	allowed, i := l.backends.AllowForwardProxy(login)

	if allowed && l.backends[i].CheckPassword(login, password) {
		return http.Continue
	}

	needAuth(ctx)
	return http.RequestEnd

}

func (mgr *policyBaseAuth) HandleHTTPCgi(ctx *http.HttpCtx, path string) http.Ret {
	token := ctx.RemoveCookie(verfiyCookieKey)

	var session *session
	var user string
	if token != "" {
		session = mgr.at(token)

		if session != nil {
			user = session.username
		}
	}

	var Maindomain = http.GetRootDomain(ctx.Req.Host)

	path = strings.TrimPrefix(path, PrefixAuth+PrefixAuthPolicy)

	r := ctx.Req.URL.Query().Get("r")
	p, err := base64.URLEncoding.DecodeString(r)
	if err != nil {
		ctx.Resp.ErrorPage(http.StatusBadRequest, "Can't decode your requested url: "+err.Error())
		return http.RequestEnd
	}

	truepath := string(p)

	if !strings.HasPrefix(truepath, "/") {
		truepath = "/" + truepath
	}

	code := mgr.determine(ctx.Req.Host, ctx.Req.URL.Path, user)

	switch path {
	case "/trace":
		ctx.Resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		var r string
		switch code {
		case 0:
			r = "nohit"
		case 1:
			r = "denied"
		case 2:
			r = "passed"
		}
		var reqalive uint64
		var last string
		var src string
		if session != nil {
			reqalive = atomic.LoadUint64(&session.active)
			user = session.username
			src = strconv.Itoa(session.src)

			session.muS.Lock()
			last = session.lastseen.Local().String()
			session.muS.Unlock()
		}

		ctx.WriteString(
			"user: " + user + "\n" +
				"vsrc: " + src + "\n" +
				"alive: " + strconv.FormatUint(reqalive, 10) + "\n" +
				"host: " + ctx.Req.Host + "\n" +
				"path: " + truepath + "\n" +
				"status: " + r + "\n" +
				"lastseen: " + last + "\n",
		)
		return http.RequestEnd
	case "/pwd":
		if session != nil {
			// ctx.Resp.RefreshRedirectPage(http.StatusConflict, truepath, "You've already logged in as "+session.user.name, 1)
			ctx.Redirect(truepath, http.StatusFound)
		} else {
			if ctx.Req.Method == "POST" {
				//get username & password
				ctx.Req.ParseForm()
				var userl, passl = ctx.Req.PostForm.Get("username"), ctx.Req.PostForm.Get("password")
				if userl == "" || passl == "" {
					ctx.Resp.RefreshRedirectPage(http.StatusBadRequest, "login?r="+r, "Username or password missing", 3)
					return http.RequestEnd
				}

				//check it
				if ok, v_src := mgr.backends.CheckPassword(userl, passl); ok {
					session := mgr.generateSession(userl, v_src)
					ctx.SetCookie(&stdhttp.Cookie{
						Name:     verfiyCookieKey,
						Value:    session,
						Domain:   Maindomain,
						Secure:   true,
						Path:     "/",
						Expires:  time.Now().Add(3 * 24 * time.Hour),
						SameSite: stdhttp.SameSiteNoneMode,
					})
					ctx.Redirect(truepath, http.StatusFound)

					log.Println("%", "^", userl, "+"+session, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
					// directly move to the truepath without checking whether the user has permission,
					// if it doesn't, the server would move it back
				} else {
					time.Sleep(200 * time.Millisecond) // Sleep 200ms to avoid being cracked
					ctx.Resp.RefreshRedirectPage(http.StatusUnauthorized, "login?r="+r, "Username or password error", 3)

					log.Println("%", "!", userl, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
				}
			} else {
				ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, "method not allowed")
			}
		}
	case "/login":
		if code == 2 {
			ctx.Redirect(truepath, http.StatusFound)
			break
		}
		if session != nil {
			ctx.Resp.Header().Set("Refresh", "5")
			ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
			ctx.Resp.WriteHeader(http.StatusForbidden)
			permission_denied.Execute(ctx.Resp, map[string]string{"r": r, "user": session.id()})
		} else {
			ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
			userlogin.Execute(ctx.Resp, struct {
				R   string
				UTC string
				DO  string
				TAR string
				RIP string
			}{R: r, TAR: ctx.Req.Host + truepath, DO: Maindomain, UTC: time.Now().UTC().Format("2006\u201101\u201102\u00A015:04:05\u00A0UTC"), RIP: ctx.RemoteIP})

		}
	case "/logout":
		ctx.SetCookie(&stdhttp.Cookie{
			Name:     verfiyCookieKey,
			Value:    "",
			Domain:   Maindomain,
			Secure:   true,
			Path:     "/",
			Expires:  time.Now().Add(-1 * time.Hour),
			SameSite: stdhttp.SameSiteNoneMode,
		})
		if session != nil {
			mgr.rmSession(token)
			log.Println("%", "-", session.id(), "+"+token, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
		}
		ctx.Resp.RefreshRedirectPage(http.StatusOK, "login?r="+r, "Successfully logged out", 2)
	default:
		ctx.Resp.ErrorPage(http.StatusNotFound, "Not Found")
	}
	return http.RequestEnd
}

func (l *policyBaseAuth) Paths() utils.GroupRegexp {
	return regexpforauthpath
}

func (mgr *policyBaseAuth) generateSession(username string, src int) string {

	var rand = utils.RandString(16)
	mgr.muSession.Lock()
	mgr.sessions[rand] = &session{
		lastseen: time.Now(),
		active:   0,
		muS:      sync.Mutex{},
		username: username,
		src:      src,
	}
	mgr.muSession.Unlock()
	return rand
}

func (mgr *policyBaseAuth) rmSession(session string) {
	if session == "" {
		return
	}
	mgr.muSession.Lock()
	delete(mgr.sessions, session)
	mgr.muSession.Unlock()
}

func (mgr *policyBaseAuth) Clean() {
	now := time.Now()
	mgr.muSession.Lock()
	for key, session := range mgr.sessions {
		if atomic.LoadUint64(&session.active) > 0 {
			continue
		}
		session.muS.Lock()
		if session.lastseen.Add(120 * time.Minute).Before(now) {
			delete(mgr.sessions, key)
			log.Println("%", "&-", session.id(), key)
		}
		session.muS.Unlock()
	}
	mgr.muSession.Unlock()
}

func (LGM *policyBaseAuth) AddPolicy(name string, allow bool, users []string, hosts []string, paths []string) error {
	p := &policy{
		name:      name,
		allowance: allow,
		users:     map[string]bool{},
		hosts:     nil,
		hup:       nil,
		paths:     nil,
	}
	for _, u := range users {
		p.users[u] = true
	}

	p.hup = utils.NewBufferedLookup(func(s string) interface{} {
		return p.hosts == nil || p.hosts.MatchString(s)
	})

	if len(hosts) != 0 {
		p.hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
	}

	if len(paths) != 0 {
		p.paths = utils.MustCompileRegexp((paths))
	}

	LGM.policies = append(LGM.policies, p)
	LGM.policyLookupBuf.Refresh()
	return nil
}

func (mgr *policyBaseAuth) determine(host, path, user string) (v uint8) {
	pls := mgr.policyLookupBuf.Lookup(host).([]*policy)
	if len(pls) == 0 {
		return 0
	}

	for _, p := range pls {
		v := p.check(user, path)
		// fmt.Println(p.name, host, path, user, v)
		if v != 0 {
			return v
		}
	}

	return 0
}

func (mgr *policyBaseAuth) AddBackends(_src []PolicyBackend) {
	mgr.backends = append(mgr.backends, _src...)
}

func (mgr *policyBaseAuth) CheckSSHKey(ctx *ssh.Ctx, key gossh.PublicKey) bool {
	for _, backend := range mgr.backends {
		if backend.CheckSSHKey(ctx, key) {
			return true
		}
	}
	return false
}
