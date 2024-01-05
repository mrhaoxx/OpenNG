package auth

import (
	"encoding/base64"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	stdhttp "net/http"

	"github.com/dlclark/regexp2"
	http "github.com/mrhaoxx/OpenNG/http"
	logging "github.com/mrhaoxx/OpenNG/logging"
	ngtls "github.com/mrhaoxx/OpenNG/tls"
	utils "github.com/mrhaoxx/OpenNG/utils"
)

const PrefixAuthPolicy string = "/pb"
const verfiyCookieKey string = "_ng_s"

type user struct {
	name         string
	passwordHash string
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
		return false
	}

	if utils.CheckPasswordHash(passwd, usr.passwordHash) {
		return true
	}

	time.Sleep(time.Millisecond * 600)

	return false
}
func GenHash(data string) string {
	hashed, _ := utils.HashPassword(data)
	return hashed
}

func (mgr *policyBaseAuth) HandleAuth(ctx *http.HttpCtx) AuthRet {
	// First Lets get user info
	cookie, _ := ctx.Req.Cookie(verfiyCookieKey)
	var session *session
	var user string
	if cookie != nil {
		mgr.muSession.RLock()
		session = mgr.sessions[cookie.Value]
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

func (mgr *policyBaseAuth) HandleHTTPInternal(ctx *http.HttpCtx) http.Ret {
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

	path := ctx.NilLoad(http.InternalPath).(string)[len(PrefixAuth+PrefixAuthPolicy):]

	r := ctx.Req.URL.Query().Get("r")
	p, err := base64.URLEncoding.DecodeString(r)
	if err != nil {
		ctx.ErrorPage(http.StatusBadRequest, "Can't decode your requested url: "+err.Error())
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
	case "/uplogin":
		if session != nil {
			ctx.ErrorPage(http.StatusConflict, "You've already logged in as "+session.user.name)
		} else {
			if ctx.Req.Method == "POST" {
				//get username & password
				ctx.Req.ParseForm()
				var userl, passl = ctx.Req.PostForm.Get("username"), ctx.Req.PostForm.Get("password")
				if userl == "" || passl == "" {
					ctx.ErrorPage(http.StatusBadRequest, "Username or password missing")
					return http.RequestEnd
				}

				user := mgr.usrs[userl]

				//check it
				if user.checkpwd(passl) {
					session := mgr.generateSession(user)
					ctx.SetCookie(&stdhttp.Cookie{
						Name:     verfiyCookieKey,
						Value:    session,
						Domain:   ctx.NilLoad(http.Maindomain).(string),
						Secure:   true,
						Path:     "/",
						Expires:  time.Now().Add(3 * 24 * time.Hour),
						SameSite: stdhttp.SameSiteNoneMode,
					})
					ctx.Redirect(truepath, http.StatusFound)

					logging.Println("%", "^", userl, "+"+session, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
					// directly move to the truepath without checking whether the user has permission,
					// if it doesn't, the server would move it back
				} else {
					time.Sleep(200 * time.Millisecond) // Sleep 200ms to avoid being cracked
					ctx.RefreshRedirectPage(http.StatusUnauthorized, "login?r="+r, "Username or password error", 5)

					logging.Println("%", "!", userl, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
				}
			} else {
				ctx.ErrorPage(http.StatusMethodNotAllowed, err.Error())
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
			Domain:   ctx.NilLoad(http.Maindomain).(string),
			Secure:   true,
			Path:     "/",
			Expires:  time.Now().Add(-1 * time.Hour),
			SameSite: stdhttp.SameSiteNoneMode,
		})
		if session != nil {
			mgr.rmSession(cookie.Value)
			logging.Println("%", "-", session.user.name, "+"+cookie.Value, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
		}
		ctx.RefreshRedirectPage(http.StatusOK, "login?r="+r, "Successfully logged out", 3)
	default:
		ctx.ErrorPage(http.StatusNotFound, "Not Found")
	}
	return http.RequestEnd
}

var regexpforit = regexp2.MustCompile("^"+PrefixAuth+PrefixAuthPolicy+"/.*$", 0)

func (l *policyBaseAuth) PathsInternal() utils.GroupRegexp {
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
			logging.Println("%", "&-", session.user.name, key)
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
		p.hosts = utils.MustCompileRegexp(ngtls.Dnsname2Regexp(hosts))
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
