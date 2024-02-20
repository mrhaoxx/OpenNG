package auth

import (
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/utils"

	"github.com/dlclark/regexp2"
)

type AuthRet uint8

const PrefixAuth = "/auth"
const InternalAuthPath = 119
const (
	AC AuthRet = 0 //accept
	DE AuthRet = 1 //deny
	CT AuthRet = 2 // next auth method
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

	ctx.Resp.ErrorPage(http.StatusForbidden, "auth no hit")
	return http.RequestEnd
}
func (l *authMgr) Hosts() utils.GroupRegexp {
	return []*regexp2.Regexp{regexpforall}
}

var regexpforall = regexp2.MustCompile("^.*$", 0)

func NewAuthMgr(h []AuthHandle) *authMgr {
	return &authMgr{h: h}
}
