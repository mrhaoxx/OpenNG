package auth

import (
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

type AuthRet uint8

// AuthRet is the return value of AuthHandle.HandleAuth
//
//   - Accept: accept the request
//   - Deny: deny the request
//   - Continue: continue to the next auth method
const (
	Accept   AuthRet = 0 //accept
	Deny     AuthRet = 1 //deny
	Continue AuthRet = 2 // next auth method
)

type AuthHandle interface {
	HandleAuth(ctx *http.HttpCtx) AuthRet
}

type authMgr struct {
	h  []AuthHandle
	ho groupexp.GroupRegexp
}

func (mgr *authMgr) HandleHTTP(ctx *http.HttpCtx) http.Ret {

	for _, h := range mgr.h {
		switch h.HandleAuth(ctx) {
		case Accept:
			return http.Continue
		case Deny:
			if ctx.Resp.Code() == 0 {
				ctx.Resp.WriteHeader(http.StatusForbidden)
			}
			return http.RequestEnd
		case Continue:
			continue
		}
	}

	ctx.Resp.ErrorPage(http.StatusForbidden, "auth no hit")
	return http.RequestEnd
}
func (l *authMgr) Hosts() groupexp.GroupRegexp {
	return l.ho
}

func NewAuthMgr(h []AuthHandle, hosts groupexp.GroupRegexp) *authMgr {
	return &authMgr{h: h, ho: hosts}
}

var _ http.Service = (*authMgr)(nil)
