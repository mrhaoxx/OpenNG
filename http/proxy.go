package http

import (
	"context"
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

var _my_cipher_suit = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
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

	var HTTPTlsConfig = tls.Config{
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       _my_cipher_suit,
		InsecureSkipVerify: InsecureSkipVerify,
	}

	var WSTlsConfig = tls.Config{
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       _my_cipher_suit,
		InsecureSkipVerify: InsecureSkipVerify,
	}

	u, _ := url.Parse(backend)
	hostport, _ := hostPortNoPort(u)

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return dialer.DialContext(ctx, network, hostport)
	}

	buf.Proxy = &httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {
			rw.(*NgResponseWriter).ErrorPage(http.StatusBadGateway, "Bad Gateway\n"+strconv.Quote(e.Error()))
			log.Println("sys", "httpproxy", r.Host, "->", id, e)
		},
		Transport: &http.Transport{
			TLSClientConfig:       &HTTPTlsConfig,
			DialContext:           dialer,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			IdleConnTimeout:       0,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxConnsPerHost:       MaxConnsPerHost,
		},
		Director: func(r *http.Request) {
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
		},
		FlushInterval: -1,
	}

	buf.WSProxy = &WebsocketProxy{
		Backend: func(r *http.Request) *url.URL {
			var u_ws *url.URL = &url.URL{
				Scheme:   "ws",
				Host:     r.Host,
				Path:     r.URL.Path,
				Opaque:   r.URL.Opaque,
				User:     r.URL.User,
				RawQuery: r.URL.RawQuery,
				Fragment: r.URL.Fragment,
			}
			if strings.HasPrefix(backend, "https") {
				u_ws.Scheme = "wss"
			}
			return u_ws
		},
		Dialer: &websocket.Dialer{
			TLSClientConfig: &WSTlsConfig,
			NetDialContext:  dialer,
		},
	}

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
