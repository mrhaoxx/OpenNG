package auth

import (
	"github.com/haoxingxing/OpenNG/http"

	"github.com/dlclark/regexp2"
)

type AuthRet uint8

const PrefixAuth = "/auth"
const InternalAuthPath = 119
const (
	AC AuthRet = 0
	DE AuthRet = 1
	CT AuthRet = 2
)

type AuthHandle interface {
	HandleAuth(ctx *http.HttpCtx) AuthRet
}
type authMgr struct {
	h []AuthHandle
}

func (mgr *authMgr) HandleHTTP(ctx *http.HttpCtx) http.Ret {

	for _, h := range mgr.h {
		switch h.HandleAuth(ctx) {
		case AC:
			return http.Continue
		case DE:
			if ctx.Resp.Code() == 0 {
				ctx.Resp.WriteHeader(http.StatusForbidden)
			}
			return http.RequestEnd
		case CT:
			continue
		}
	}

	ctx.ErrorPage(http.StatusForbidden, "auth no hit")
	return http.RequestEnd
}
func (l *authMgr) Hosts() []*regexp2.Regexp {
	return []*regexp2.Regexp{regexpforall}
}
func (l *authMgr) HandleHTTPInternal(ctx *http.HttpCtx) http.Ret {
	ctx.Store(InternalAuthPath, ctx.NilLoad(http.InternalPath).(string)[len(PrefixAuth):])
	
}

var regexpforall = regexp2.MustCompile("^.*$", 0)
var regexpforit = regexp2.MustCompile("^"+PrefixAuth+"/.*$", 0)

func (l *authMgr) PathsInternal() []*regexp2.Regexp {
	return []*regexp2.Regexp{regexpforit}
}

func NewAuthMgr(h []AuthHandle) *authMgr {
	return &authMgr{h: h}
}
