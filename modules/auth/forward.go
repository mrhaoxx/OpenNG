package auth

import (
	"encoding/base64"
	"strings"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
)

func needAuth(ctx *nghttp.HttpCtx) {
	ctx.Resp.Header().Set("Proxy-Authenticate", "Basic realm=\""+netgate.ServerSign+"\"")
	ctx.Resp.WriteHeader(nghttp.StatusProxyAuthRequired)
}

func (l *PolicyBaseAuth) HandleHTTPForward(ctx *nghttp.HttpCtx) nghttp.Ret {
	hdr := ctx.Req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		needAuth(ctx)
		return nghttp.RequestEnd
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		needAuth(ctx)
		return nghttp.RequestEnd
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		needAuth(ctx)
		return nghttp.RequestEnd
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		needAuth(ctx)
		return nghttp.RequestEnd
	}

	login := pair[0]
	password := pair[1]

	allowed, i := l.backends.AllowForwardProxy(login)

	if allowed && l.backends[i].CheckPassword(login, password) {
		return nghttp.Continue
	}

	needAuth(ctx)
	return nghttp.RequestEnd
}

func (mgr *PolicyBaseAuth) HandleSocks5(username string, password string, userAddr string) bool {
	allowed, i := mgr.backends.AllowForwardProxy(username)
	if allowed && mgr.backends[i].CheckPassword(username, password) {
		return true
	}
	return false
}

func (*PolicyBaseAuth) HostsForward() groupexp.GroupRegexp {
	return nil
}
