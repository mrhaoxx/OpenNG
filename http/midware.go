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

	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/log"
	tcp "github.com/mrhaoxx/OpenNG/tcp"
	utils "github.com/mrhaoxx/OpenNG/utils"
	"golang.org/x/net/http2"

	"github.com/dlclark/regexp2"
)

//ng:generate def obj Midware
type Midware struct {
	current               []*ServiceStruct
	bufferedLookupForHost utils.BufferedLookup
	bufferedLookupForSNI  utils.BufferedLookup

	proxychan []ServiceHandler

	services map[string]Service

	sni utils.GroupRegexp

	muActiveRequest sync.RWMutex
	activeRequests  map[uint64]*HttpCtx
}
type ServiceStruct struct {
	ServiceHandler
	Id    string
	Hosts utils.GroupRegexp
}

// //dng:generate def func Midware::AddService
// //@Desc Add service to midware
// //@Param string name the service's registered name
// //@Param _nocheck:Service s the service
// func (h *Midware) AddService(name string, s Service) error {
// 	h.services[name] = s
// 	return nil
// }

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
		if RequestCtx.Req.Method == "CONNECT" || ok {
			RequestPath += "> "
			h.ngForwardProxy(RequestCtx)
			RequestPath += "-"
			return
		}
	}
	// internal content handle
	if strings.HasPrefix(RequestCtx.Req.URL.Path, PrefixNg) {
		if ngInternalServiceHandler(RequestCtx) != Continue {
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

type Service interface {
	Hosts() utils.GroupRegexp
	HandleHTTP(*HttpCtx) Ret
}
type ServiceInternal interface {
	PathsInternal() utils.GroupRegexp
	HandleHTTPInternal(*HttpCtx, string) Ret
}

func NewHttpMidware(sni []string) *Midware {
	hmw := &Midware{
		services:       map[string]Service{},
		sni:            nil,
		activeRequests: map[uint64]*HttpCtx{},
	}
	hmw.current = make([]*ServiceStruct, 0)
	hmw.bufferedLookupForHost = *utils.NewBufferedLookup(func(s string) interface{} {
		ret := make([]*ServiceStruct, 0)
		for _, r := range hmw.current {
			if r.Hosts.MatchString(s) {
				ret = append(ret, r)
			}
		}
		return ret
	})
	hmw.bufferedLookupForSNI = *utils.NewBufferedLookup(func(s string) interface{} {
		return hmw.sni == nil || hmw.sni.MatchString(s)
	})
	hmw.sni = utils.MustCompileRegexp(dns.Dnsnames2Regexps(sni))
	return hmw
}

type serviceholder struct {
	sl    ServiceHandler
	il    ServiceHandler
	hosts []*regexp2.Regexp
	paths []*regexp2.Regexp
}

func (h *serviceholder) PathsInternal() utils.GroupRegexp {
	return h.paths
}

func (h *serviceholder) HandleHTTPInternal(ctx *HttpCtx) Ret {
	return h.il(ctx)
}

func (h *serviceholder) Hosts() utils.GroupRegexp {
	return h.hosts
}
func (h *serviceholder) HandleHTTP(ctx *HttpCtx) Ret {
	return h.sl(ctx)
}

func NewServiceHolder(hosts utils.GroupRegexp, sl ServiceHandler, paths utils.GroupRegexp, il ServiceHandler) Service {
	return &serviceholder{
		sl:    sl,
		il:    il,
		hosts: hosts,
		paths: paths,
	}
}

// @Desc Get the binded services of the http midware
// @RetVal []*ServiceStruct the binded services
//
//ng:generate def func Midware::GetBind
func (HMW *Midware) GetBind() []*ServiceStruct {
	return HMW.current
}

func (HMW *Midware) AddService(id string, svc Service) {
	HMW.services[id] = svc
	// if p := svc.PathsInternal(); p != nil {
	// 	addInternal(svc.HandleHTTPInternal, p)
	// }
}
func (HMW *Midware) AddServiceInternal(svc ServiceInternal) {
	// HMW.services[id] = svc
	// if p := svc.PathsInternal(); p != nil {
	addInternal(svc.HandleHTTPInternal, svc.PathsInternal())
	// }
}

// @Desc Bind a service to the http midware
// @Param string id the id of the service
// @Param string id identificator of the service
// @OptionalParam []string=[]string{"(.*)"} hosts the specificed hosts
//
//ng:generate def func Midware::Bind
func (HMW *Midware) Bind(serviceid string, id string, _hosts []string) error {
	if id == "" {
		id = serviceid
	}
	var hosts []*regexp2.Regexp
	service, ok := HMW.services[serviceid]
	if !ok {
		return errors.New("service " + serviceid + " not found")
	}
	if len(_hosts) == 0 {
		hosts = service.Hosts()
	} else {
		hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(_hosts))
	}
	HMW.current = append(HMW.current, &ServiceStruct{
		Id:             id,
		Hosts:          hosts,
		ServiceHandler: service.HandleHTTP,
	})

	HMW.bufferedLookupForHost.Refresh()
	return nil
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
