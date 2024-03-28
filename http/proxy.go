package http

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/utils"

	"github.com/dlclark/regexp2"
)

type Httphost struct {
	Id         string
	ServerName utils.GroupRegexp
	Proxy      *httputil.ReverseProxy
	WSProxy    *WebsocketProxy
	Backend    string
}

//ng:generate def obj httpproxy
type httpproxy struct {
	hosts []*Httphost
	buf   *utils.BufferedLookup
}

func (h *httpproxy) HandleHTTPCgi(ctx *HttpCtx, path string) Ret {
	_host := h.buf.Lookup(ctx.Req.Host)
	var id string
	if _host != nil {
		id = _host.(*Httphost).Id
	} else {
		id = "nohit"
	}

	ctx.WriteString("id: " + id + "\n")
	return RequestEnd
}
func (*httpproxy) Paths() utils.GroupRegexp {
	return []*regexp2.Regexp{regexpforproxy}
}

var regexpforproxy = regexp2.MustCompile("^/proxy/trace$", 0)

func NewHTTPProxier() *httpproxy {
	hpx := &httpproxy{
		hosts: make([]*Httphost, 0),
		buf:   nil,
	}
	hpx.buf = utils.NewBufferedLookup(func(host string) interface{} {
		for _, t := range hpx.hosts {
			if t.ServerName.MatchString(host) {
				// fmt.Println(t.ServerName.String(), host, "success")
				return t
			}
			// fmt.Println(t.ServerName.String(), host, "failed")
		}
		return nil
	})
	return hpx
}

func (h *httpproxy) HandleHTTP(ctx *HttpCtx) Ret {
	_host := h.buf.Lookup(ctx.Req.Host)
	if _host == nil {
		return Continue
	}
	host := _host.(*Httphost)

	defer func() {
		recover()
	}()

	if ctx.Req.Header.Get("Upgrade") == "websocket" {
		host.WSProxy.ServeHTTP(ctx.Resp, ctx.Req)
	} else {
		host.Proxy.ServeHTTP(ctx.Resp, ctx.Req)
	}
	return RequestEnd
}

var catchallexp = []*regexp2.Regexp{regexp2.MustCompile("^.*$", 0)}

func (h *httpproxy) Hosts() utils.GroupRegexp {
	return catchallexp
}

// @RetVal []*Httphost hosts of proxy
//
//ng:generate def func httpproxy::GetHosts
func (hpx *httpproxy) GetHosts() []*Httphost {
	return hpx.hosts
}

// @Param string id id of proxy
// @RetVal error
//
//ng:generate def func httpproxy::Delete
func (hpx *httpproxy) Delete(id string) error {
	for i, v := range hpx.hosts {
		if v.Id == id {
			hpx.hosts = append(hpx.hosts[:i], hpx.hosts[i+1:]...)
			hpx.buf.Refresh()
			return nil
		}
	}
	return errors.New("not found")
}

// @Param int index index to insert
// @Param string id id of proxy
// @Param []string host list of host
// @Param string backend backend of proxy
// @OptionalParam int=0 TransportArgs::MaxConnsPerHost max connections per host
// @OptionalParam bool=false TransportArgs::InsecureSkipVerify skip verify
//
//ng:generate def func httpproxy::Insert
func (hpx *httpproxy) Insert(index int, id string, hosts []string, backend string, MaxConnsPerHost int, InsecureSkipVerify bool) error {
	buf := Httphost{
		Id:         id,
		ServerName: utils.MustCompileRegexp(dns.Dnsnames2Regexps(hosts)),
		Backend:    backend,
	}

	var tlsc = tls.Config{NextProtos: []string{"http/1.1"}}
	var tpa = &http.Transport{
		TLSClientConfig: &tlsc,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          0,
		IdleConnTimeout:       0,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tpa.MaxConnsPerHost = MaxConnsPerHost
	tlsc.InsecureSkipVerify = InsecureSkipVerify
	u, _ := url.Parse(backend)
	buf.Proxy = &httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {
			// rw.(*NgResponseWriter).Header().Add("X-Ng-Proxy-Err", strconv.Quote(e.Error()))
			rw.(*NgResponseWriter).ErrorPage(http.StatusBadGateway, "Bad Gateway\n"+strconv.Quote(e.Error()))
			log.Println("sys", "httpproxy", r.Host, "->", id, e)
		},
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.Host = u.Host
		},
		Transport:     tpa,
		FlushInterval: 0,
	}
	u_ws, _ := url.Parse(strings.Replace(backend, "http", "ws", 1))
	buf.WSProxy = NewWSProxy(u_ws)
	buf.WSProxy.Dialer = &websocket.Dialer{TLSClientConfig: &tlsc}
	hpx.hosts = insert(hpx.hosts, index, &buf)
	return nil
}
func insert(a []*Httphost, index int, value *Httphost) []*Httphost {
	if index < 0 {
		panic(errors.New("index out of range"))
	}
	if len(a) == index {
		a = append(a, value)
	} else {
		a = append(a[:index+1], a[index:]...)
		a[index] = value
	}
	return a
}

// @Param string id id of proxy
// @Param []string host list of host
// @Param string backend backend of proxy
// @OptionalParam int=0 TransportArgs::MaxConnsPerHost max connections per host
// @OptionalParam bool=false TransportArgs::InsecureSkipVerify skip verify
//
//ng:generate def func httpproxy::Add
func (hpx *httpproxy) Add(id string, hosts []string, backend string, MaxConnsPerHost int, InsecureSkipVerify bool) error {
	return hpx.Insert(len(hpx.hosts), id, hosts, backend, MaxConnsPerHost, InsecureSkipVerify)
}

//ng:generate def func httpproxy::Reset
func (hpx *httpproxy) Reset() error {
	hpx.hosts = make([]*Httphost, 0)
	hpx.buf.Refresh()
	return nil
}
