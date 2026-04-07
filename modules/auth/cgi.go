package auth

import (
	"encoding/base64"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	stdhttp "net/http"

	"github.com/mrhaoxx/OpenNG/modules/groupexp"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"

	zlog "github.com/rs/zerolog/log"
)

func (mgr *policyBaseAuth) HandleHTTPCgi(ctx *nghttp.HttpCtx, path string) nghttp.Ret {
	token := ctx.RemoveCookie(verfiyCookieKey)

	var session *session
	var user string
	if token != "" {
		session = mgr.at(token)

		if session != nil {
			user = session.username
		}
	}

	var Maindomain = nghttp.GetRootDomain(ctx.Req.Host)

	path = strings.TrimPrefix(path, PrefixAuth+PrefixAuthPolicy)

	r := ctx.Req.URL.Query().Get("r")
	p, err := base64.URLEncoding.DecodeString(r)
	if err != nil {
		ctx.Resp.ErrorPage(nghttp.StatusBadRequest, "Can't decode your requested url: "+err.Error())
		return nghttp.RequestEnd
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
		return nghttp.RequestEnd
	case "/pwd":
		if session != nil {
			// ctx.Resp.RefreshRedirectPage(http.StatusConflict, truepath, "You've already logged in as "+session.user.name, 1)
			ctx.Redirect(truepath, nghttp.StatusFound)
		} else {
			if ctx.Req.Method == "POST" {
				//get username & password
				ctx.Req.ParseForm()
				var userl, passl = ctx.Req.PostForm.Get("username"), ctx.Req.PostForm.Get("password")
				if userl == "" || passl == "" {
					ctx.Resp.RefreshRedirectPage(nghttp.StatusBadRequest, "login?r="+r, "Username or password missing", 3)
					return nghttp.RequestEnd
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
					ctx.Redirect(truepath, nghttp.StatusFound)

					// log.Println("%", "^", userl, "+"+session, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)

					zlog.Info().
						Str("type", "auth/login").
						Str("status", "passed").
						Str("user", userl).
						Str("session", session).
						Str("reqid", ctx.Id).
						Str("ip", ctx.RemoteIP).
						Int("port", ctx.RemotePort).
						Msg("")

					// directly move to the truepath without checking whether the user has permission,
					// if it doesn't, the server would move it back
				} else {
					time.Sleep(time.Duration(200+rand.Intn(100)) * time.Millisecond) // Sleep 200ms to avoid being cracked
					ctx.Resp.RefreshRedirectPage(nghttp.StatusUnauthorized, "login?r="+r, "Username or password error", 3)

					// log.Println("%", "!", userl, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)

					zlog.Info().
						Str("type", "auth/login").
						Str("status", "failed").
						Str("user", userl).
						Str("reqid", ctx.Id).
						Str("ip", ctx.RemoteIP).
						Int("port", ctx.RemotePort).
						Msg("")
				}
			} else {
				ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "method not allowed")
			}
		}
	case "/login":
		if code == 2 {
			ctx.Redirect(truepath, nghttp.StatusFound)
			break
		}
		if session != nil {
			ctx.Resp.Header().Set("Refresh", "5")
			ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
			ctx.Resp.WriteHeader(nghttp.StatusForbidden)
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
			// log.Println("%", "-", session.id(), "+"+token, "r"+strconv.FormatUint(ctx.Id, 10), ctx.Req.RemoteAddr)
			zlog.Info().
				Str("type", "auth/logout").
				Str("reason", "manual").
				Str("user", session.username).
				Str("session", token).
				Str("reqid", ctx.Id).
				Str("ip", ctx.RemoteIP).
				Int("port", ctx.RemotePort).
				Msg("")
		}
		ctx.Resp.RefreshRedirectPage(nghttp.StatusOK, "login?r="+r, "Successfully logged out", 2)
	default:
		ctx.Resp.ErrorPage(nghttp.StatusNotFound, "Not Found")
	}
	return nghttp.RequestEnd
}

func (l *policyBaseAuth) CgiPaths() groupexp.GroupRegexp {
	return regexpforauthpath
}
