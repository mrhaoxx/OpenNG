package auth

import (
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/nghttp"
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
	HandleAuth(ctx *nghttp.HttpCtx) AuthRet
}

type authMgr struct {
	h  []AuthHandle
	ho groupexp.GroupRegexp
}

func (mgr *authMgr) HandleHTTP(ctx *nghttp.HttpCtx) nghttp.Ret {

	for _, h := range mgr.h {
		switch h.HandleAuth(ctx) {
		case Accept:
			return nghttp.Continue
		case Deny:
			if ctx.Resp.Code() == 0 {
				ctx.Resp.WriteHeader(nghttp.StatusForbidden)
			}
			return nghttp.RequestEnd
		case Continue:
			continue
		}
	}

	ctx.Resp.ErrorPage(nghttp.StatusForbidden, "auth no hit")
	return nghttp.RequestEnd
}
func (l *authMgr) Hosts() groupexp.GroupRegexp {
	return l.ho
}

func NewAuthMgr(h []AuthHandle, hosts groupexp.GroupRegexp) *authMgr {
	return &authMgr{h: h, ho: hosts}
}

var _ nghttp.Service = (*authMgr)(nil)
