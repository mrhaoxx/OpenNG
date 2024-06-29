package auth

import (
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/utils"
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
	ho utils.GroupRegexp
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
func (l *authMgr) Hosts() utils.GroupRegexp {
	return l.ho
}

// NewAuthMgr creates a new authMgr. It requires a list of AuthHandle for auth mechanism and a GroupRegexp for host matching.
// eg. Create A new AuthMgr that matches all hosts:
//
//	var auth = auth.NewAuthMgr([]auth.AuthHandle{}, utils.GroupRegexp{regexp2.MustCompile("^.*$", 0)})
func NewAuthMgr(h []AuthHandle, hosts utils.GroupRegexp) *authMgr {
	return &authMgr{h: h, ho: hosts}
}
