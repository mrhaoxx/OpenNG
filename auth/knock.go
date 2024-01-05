package auth

import (
	"net"
	"sync"

	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/utils"
)

type knockauthMgr struct {
	whitelist sync.Map
}

func (mgr *knockauthMgr) Handle(c *tcp.Conn) tcp.SerRet {
	host, _, _ := net.SplitHostPort(c.Addr().String())
	esx, ok := mgr.whitelist.Load(host)
	if ok && esx.(bool) {
		return tcp.Continue
	} else {
		return tcp.Close
	}
}
func (mgr *knockauthMgr) HandleHTTP(ctx *http.HttpCtx) http.Ret {
	host, _, _ := net.SplitHostPort(ctx.Req.RemoteAddr)
	if ctx.Req.URL.Path != "/" {
		host = ctx.Req.URL.Path[1:]
	}
	if _, ok := mgr.whitelist.Load(host); ok {
		ctx.Resp.WriteHeader(http.StatusOK)
		ctx.WriteString("DOOR OPENED ALREADY\n" + host)
	} else {
		mgr.whitelist.Store(host, true)
		ctx.WriteString("DOOR OPEN\n" + host)
	}
	return http.RequestEnd
}

func (mgr *knockauthMgr) Hosts() utils.GroupRegexp {
	return nil
}
func NewKnockMgr() *knockauthMgr {
	mgr := &knockauthMgr{}
	return mgr
}
