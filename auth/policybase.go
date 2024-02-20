package auth

import (
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stdhttp "net/http"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/dns"
	http "github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	utils "github.com/mrhaoxx/OpenNG/utils"
)

const PrefixAuthPolicy string = "/pb"
const verfiyCookieKey string = "_ng_s"

type user struct {
	name                string
	passwordHash        string
	allow_forward_proxy bool

	passwordmap sync.Map
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

type policyBaseAuth struct {
	policies        []*policy
	policyLookupBuf *utils.BufferedLookup

	usrs map[string]*user

	sessions  map[string]*session
	muSession sync.RWMutex
}

type session struct {
	lastseen time.Time
	active   uint64

	muS  sync.Mutex
	user *user
}

func NewPBAuth() *policyBaseAuth {
	po := &policyBaseAuth{
		usrs:     map[string]*user{},
		sessions: map[string]*session{},
	}

	po.policyLookupBuf = utils.NewBufferedLookup(func(s string) interface{} {
		var r []*policy = nil
		for _, p := range po.policies {
			if p.hosts.MatchString(s) {
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
func GenHash(data string) string {
	hashed, _ := utils.HashPassword(data)
	return hashed
}

func (mgr *policyBaseAuth) HandleAuth(ctx *http.HttpCtx) AuthRet {
	// First Lets get user info
	var token string
	var exists bool
	cookieHeader := ctx.Req.Header["Cookie"]
	for i, cookie := range cookieHeader {
		cookies := strings.Split(cookie, ";")
		for j, item := range cookies {
			if strings.Contains(item, verfiyCookieKey+"=") {
				token = strings.TrimPrefix(strings.TrimSpace(item), verfiyCookieKey+"=")
				cookies = append(cookies[:j], cookies[j+1:]...)
				exists = true
				break
			}
		}
		cookieHeader[i] = strings.Join(cookies, ";")
	}

	if exists {
		ctx.Req.Header["Cookie"] = cookieHeader
	}

	var session *session
	var user string
	if token != "" {
		mgr.muSession.RLock()
		session = mgr.sessions[token]
		mgr.muSession.RUnlock()

		if session != nil {
			user = session.user.name
			session.updateSession()
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

		return AC
	case 0:
		return CT // no hit
	case 1:
		url := http.PrefixNg + PrefixAuth + PrefixAuthPolicy + "/login?r=" + base64.URLEncoding.EncodeToString([]byte(ctx.Req.RequestURI))
		ctx.Redirect(url, http.StatusFound) //auth required
	}

	return DE

}

func needAuth(ctx *http.HttpCtx) {
	ctx.Resp.Header().Set("Proxy-Authenticate", "Basic realm=\"NetGATE\"")
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

	user := l.usrs[login]
	if user == nil {
		needAuth(ctx)
		return http.RequestEnd
	}

	if user.allow_forward_proxy && user.checkpwd(password) {
		return http.Continue
	}

	needAuth(ctx)
	return http.RequestEnd

}

func (mgr *policyBaseAuth) HandleHTTPCgi(ctx *http.HttpCtx, path string) http.Ret {
	cookie, _ := ctx.Req.Cookie(verfiyCookieKey)
	var session *session
	var user string
	if cookie != nil {
		mgr.muSession.RLock()
		session = mgr.sessions[cookie.Value]
		mgr.muSession.RUnlock()

		if session != nil {
			user = session.user.name
		}
	}
	var Maindomain string
	n := strings.Split(ctx.Req.Host, ".")
	if len(n) >= 2 {
		rawh := strings.Join(n[len(n)-2:], ".")
		n = strings.Split(rawh, ":")
		Maindomain = n[0]
	} else {
		Maindomain = ctx.Req.Host
	}

	path = strings.TrimPrefix(path, PrefixAuth+PrefixAuthPolicy)

	r := ctx.Req.URL.Query().Get("r")
	p, err := base64.URLEncoding.DecodeString(r)
	if err != nil {
		ctx.Resp.ErrorPage(http.StatusBadRequest, "Can't decode your requested url: "+err.Error())
		return http.RequestEnd
	}

	truepath := string(p)
	if truepath == "" {
		truepath = "/"
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
		if session != nil {
			reqalive = atomic.LoadUint64(&session.active)
			user = session.user.name

			session.muS.Lock()
			last = session.lastseen.Local().String()
			session.muS.Unlock()
		}

		ctx.WriteString(
			"user: " + user + "\n" +
				"alive: " + strconv.FormatUint(reqalive, 10) + "\n" +
				"host: " + ctx.Req.Host + "\n" +
				"path: " + truepath + "\n" +
				"status: " + r + "\n" +
				"lastseen: " + last + "\n",
		)
		return http.RequestEnd
	case "/pwd":
		if session != nil {
			ctx.Resp.ErrorPage(http.StatusConflict, "You've already logged in as "+session.user.name)
		} else {
			if ctx.Req.Method == "POST" {
				//get username & password
				ctx.Req.ParseForm()
				var userl, passl = ctx.Req.PostForm.Get("username"), ctx.Req.PostForm.Get("password")
				if userl == "" || passl == "" {
					ctx.Resp.ErrorPage(http.StatusBadRequest, "Username or password missing")
					return http.RequestEnd
				}

				user := mgr.usrs[userl]

				//check it
				if user.checkpwd(passl) {
					session := mgr.generateSession(user)
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
					ctx.Resp.RefreshRedirectPage(http.StatusUnauthorized, "login?r="+r, "Username or password error", 1)

					log.Println("%", "!", userl, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
				}
			} else {
				ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, err.Error())
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
			permission_denied.Execute(ctx.Resp, map[string]string{"r": r, "user": session.user.name})
		} else {
			ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
			userlogin.Execute(ctx.Resp, r)
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
			mgr.rmSession(cookie.Value)
			log.Println("%", "-", session.user.name, "+"+cookie.Value, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
		}
		ctx.Resp.RefreshRedirectPage(http.StatusOK, "login?r="+r, "Successfully logged out", 2)
	default:
		ctx.Resp.ErrorPage(http.StatusNotFound, "Not Found")
	}
	return http.RequestEnd
}

var regexpforit = regexp2.MustCompile("^"+PrefixAuth+PrefixAuthPolicy+"/.*$", 0)

func (l *policyBaseAuth) Paths() utils.GroupRegexp {
	return []*regexp2.Regexp{regexpforit}
}

func (mgr *policyBaseAuth) generateSession(usr *user) string {
	if usr == nil {
		return ""
	}

	var rand = utils.RandString(16)
	mgr.muSession.Lock()
	mgr.sessions[rand] = &session{
		lastseen: time.Now(),
		active:   0,
		muS:      sync.Mutex{},
		user:     usr,
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

func (u *session) updateSession() {
	u.muS.Lock()
	u.lastseen = time.Now()
	u.muS.Unlock()
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
			log.Println("%", "&-", session.user.name, key)
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
		hosts:     []*regexp2.Regexp{},
		hup:       nil,
		paths:     []*regexp2.Regexp{},
	}
	for _, u := range users {
		p.users[u] = true
	}
	p.hup = utils.NewBufferedLookup(func(s string) interface{} {
		return p.hosts.MatchString(s)
	})

	if len(hosts) == 0 {
		p.hosts = append(p.hosts, regexpforall)
	} else {
		p.hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts))
	}

	if len(paths) == 0 {
		p.paths = append(p.paths, regexpforall)
	} else {
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

func (LGM *policyBaseAuth) SetUser(username string, passwordhash string, allow_forward_proxy bool) {
	LGM.usrs[username] = &user{
		name:                username,
		passwordHash:        passwordhash,
		allow_forward_proxy: allow_forward_proxy,
	}
}
