package http

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/res"
	tcp "github.com/mrhaoxx/OpenNG/tcp"
	utils "github.com/mrhaoxx/OpenNG/utils"
	"golang.org/x/net/http2"
)

//ng:generate def obj Midware
type Midware struct {
	sni                  utils.GroupRegexp
	bufferedLookupForSNI *utils.BufferedLookup

	current               []*ServiceStruct
	bufferedLookupForHost *utils.BufferedLookup

	currentCgi           []*CgiStruct
	bufferedLookupForCgi *utils.BufferedLookup

	currentProxy []ServiceHandler

	muActiveRequest sync.RWMutex
	activeRequests  map[uint64]*HttpCtx
}

type ServiceHandler func(*HttpCtx) Ret

type ServiceStruct struct {
	ServiceHandler
	Id    string
	Hosts utils.GroupRegexp
}

type CgiHandler func(*HttpCtx, string) Ret

type CgiStruct struct {
	CgiHandler
	Paths utils.GroupRegexp
}
type Service interface {
	Hosts() utils.GroupRegexp
	HandleHTTP(*HttpCtx) Ret
}
type Cgi interface {
	Paths() utils.GroupRegexp
	HandleHTTPCgi(*HttpCtx, string) Ret
}

func (mid *Midware) AddServices(svc ...*ServiceStruct) {
	mid.current = append(mid.current, svc...)
	mid.bufferedLookupForHost.Refresh()
}

func (mid *Midware) AddCgis(svcs ...Cgi) {
	for _, svc := range svcs {
		mid.currentCgi = append(mid.currentCgi, &CgiStruct{
			CgiHandler: svc.HandleHTTPCgi,
			Paths:      svc.Paths(),
		})
	}
	mid.bufferedLookupForCgi.Refresh()
}

func (h *Midware) Handle(c *tcp.Conn) tcp.SerRet {
	top := c.TopProtocol()
	sni, _ := c.Load(tcp.KeyTlsSni)
	if !h.bufferedLookupForSNI.Lookup(sni.(string)).(bool) {
		return tcp.Continue
	}
	switch top {
	case "HTTP1":
		http.Serve(utils.ConnGetSocket(c.TopConn()), http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			h.head(rw, r, c)
		}))
		return tcp.Close
	case "HTTP2":
		h2s.ServeConn(c.TopConn(), &http2.ServeConnOpts{
			Handler: (http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				h.head(rw, r, c)
			})),
		})
		return tcp.Close
	default:
		return tcp.Continue
	}
}

func (h *Midware) Process(RequestCtx *HttpCtx) {
	h.muActiveRequest.Lock()
	h.activeRequests[RequestCtx.Id] = RequestCtx
	h.muActiveRequest.Unlock()

	defer RequestCtx.Resp.Close()

	var RequestPath string // record the path of the request

	defer func() { //cleanup
		if RequestCtx.Resp.code == 0 {
			RequestCtx.Resp.ErrorPage(http.StatusTeapot, "It seems the server is not responding.")
			RequestPath += "#"
		}

		RequestCtx.Close()

		h.muActiveRequest.Lock()
		delete(h.activeRequests, RequestCtx.Id)
		h.muActiveRequest.Unlock()

		if RequestCtx.Req.Host == "" {
			RequestCtx.Req.Host = "~"
		}

		if RequestCtx.Req.URL.Path == "" {
			RequestCtx.Req.URL.Path = "~"
		}

		log.Println("r"+strconv.FormatUint(RequestCtx.Id, 10), RequestCtx.Req.RemoteAddr, time.Since(RequestCtx.starttime).Round(1*time.Microsecond),
			"c"+strconv.FormatUint(RequestCtx.conn.Id, 10),
			RequestCtx.Resp.code, RequestCtx.Resp.encoding.String(), RequestCtx.Resp.writtenBytes,
			RequestCtx.Req.Method, RequestCtx.Req.Host, RequestCtx.Req.URL.Path, RequestPath)
	}()

	defer func() {
		if err := recover(); err != nil {
			if e, ok := err.(error); ok {
				RequestPath += "$<" + e.Error() + "> "
			} else {
				RequestPath += "$<> "
			}

			if RequestCtx.Resp.code == 0 {
				RequestCtx.Resp.ErrorPage(http.StatusInternalServerError, fmt.Sprintf("Panic: %v", err))
			}
		}
	}()

	// forward proxy handle
	{
		_, ok := RequestCtx.Req.Header["Proxy-Authorization"]
		if ok || RequestCtx.Req.Method == "CONNECT" {
			RequestPath += "> "
			h.ngForwardProxy(RequestCtx)
			RequestPath += "-"
			return
		}
	}
	// cgi content handle
	if strings.HasPrefix(RequestCtx.Req.URL.Path, PrefixNg) {
		if h.ngCgi(RequestCtx) != Continue {
			RequestPath += "@"
			return
		}
	}

	{
		ServicesToExecute := h.bufferedLookupForHost.Lookup(RequestCtx.Req.Host).([]*ServiceStruct)
		for i := 0; i < len(ServicesToExecute); i++ {

			RequestPath += ServicesToExecute[i].Id + " " // record the executed service
			switch ServicesToExecute[i].ServiceHandler(RequestCtx) {
			case RequestEnd:
				RequestPath += "-"
				return
			case Continue:
				continue
			}
		}
	}

}

func NewHttpMidware(sni []string) *Midware {
	hmw := &Midware{
		sni:            nil,
		activeRequests: map[uint64]*HttpCtx{},
	}
	hmw.current = make([]*ServiceStruct, 0)

	hmw.currentCgi = []*CgiStruct{{
		CgiHandler: func(ctx *HttpCtx, path string) Ret {
			ctx.Resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")
			ctx.WriteString("reqid: " + strconv.Itoa(int(ctx.Id)) + "\n" +
				"timestamp: " + strconv.FormatInt(time.Now().UnixMilli(), 10) + "\n" +
				"hostname: " + ctx.Req.Host + "\n" +
				"connection: " + strconv.Itoa(int(ctx.conn.Id)) + "\n" +
				"protocols: " + ctx.conn.Protocols() + "\n" +
				"remoteip: " + ctx.Req.RemoteAddr + "\n")
			return RequestEnd
		},
		Paths: []*regexp2.Regexp{regexp2.MustCompile("^/trace$", regexp2.None)},
	},
		{
			CgiHandler: func(ctx *HttpCtx, path string) Ret {
				res.WriteLogo(ctx.Resp)
				return RequestEnd
			},
			Paths: []*regexp2.Regexp{regexp2.MustCompile("^/logo$", regexp2.None)},
		}}

	hmw.bufferedLookupForHost = utils.NewBufferedLookup(func(s string) interface{} {
		ret := make([]*ServiceStruct, 0)
		for _, r := range hmw.current {
			if r.Hosts.MatchString(s) {
				ret = append(ret, r)
			}
		}
		return ret
	})
	hmw.bufferedLookupForCgi = utils.NewBufferedLookup(func(s string) interface{} {
		var m []*CgiStruct = nil
		for _, t := range hmw.currentCgi {
			for _, r := range t.Paths {
				if ok, _ := r.MatchString(s); ok {
					m = append(m, t)
				}
			}
		}
		return m
	})

	hmw.bufferedLookupForSNI = utils.NewBufferedLookup(func(s string) interface{} {
		return hmw.sni == nil || hmw.sni.MatchString(s)
	})
	hmw.sni = utils.MustCompileRegexp(dns.Dnsnames2Regexps(sni))
	return hmw
}

func (ctl *Midware) ReportActiveRequests() map[uint64]interface{} {
	ctl.muActiveRequest.RLock()
	defer ctl.muActiveRequest.RUnlock()
	ret := make(map[uint64]interface{})
	for _, req := range ctl.activeRequests {
		ret[req.Id] = map[string]interface{}{
			"code":        req.Resp.code,                             // FIXME: race r
			"src":         req.Req.RemoteAddr,                        // unsync r
			"starttime":   req.starttime,                             // unsync r
			"protocol":    req.Req.Proto,                             // unsync r
			"uri":         req.Req.RequestURI,                        // unsync r
			"respwritten": atomic.LoadUint64(&req.Resp.writtenBytes), // atomic
			"cid":         req.conn.Id,                               // unsync r
			"method":      req.Req.Method,                            // unsync r
			"enc":         req.Resp.encoding.String(),                // FIXME: race r
			"host":        req.Req.Host,                              // unsync r
		}
	}
	return ret
}

func (HMW *Midware) KillRequest(rid uint64) error {
	HMW.muActiveRequest.RLock()
	defer HMW.muActiveRequest.RUnlock()
	ctx, ok := HMW.activeRequests[rid]
	if !ok {
		return errors.New("request not found")
	}

	ctx.kill()

	return nil
}

type redirectTLS struct{}

func (redirectTLS) Handle(conn *tcp.Conn) tcp.SerRet {
	http.Serve(utils.ConnGetSocket(conn.TopConn()), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusPermanentRedirect)
	}))
	return tcp.Close
}

var Redirect2TLS = redirectTLS{}
