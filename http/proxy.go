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
)

type HttpHost struct {
	Id         string
	ServerName utils.GroupRegexp
	proxy      *httputil.ReverseProxy
	wsproxy    *WebsocketProxy
	Backend    string
}

//ng:generate def obj httpproxy
type httpproxy struct {
	hosts []*HttpHost
	buf   *utils.BufferedLookup

	allowhosts utils.GroupRegexp
}

func (h *httpproxy) HandleHTTPCgi(ctx *HttpCtx, path string) Ret {
	_host := h.buf.Lookup(ctx.Req.Host)
	var id string
	if _host != nil {
		id = _host.(*HttpHost).Id
	} else {
		id = "nohit"
	}

	ctx.WriteString("id: " + id + "\n")
	return RequestEnd
}
func (*httpproxy) CgiPaths() utils.GroupRegexp {
	return regexpforproxy
}

func NewHTTPProxier(allowedhosts []string) *httpproxy {
	hpx := &httpproxy{
		hosts:      make([]*HttpHost, 0),
		allowhosts: utils.MustCompileRegexp(dns.Dnsnames2Regexps(allowedhosts)),
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

	host := _host.(*HttpHost)

	defer func() {
		recover()
	}()

	if ctx.Req.Header.Get("Upgrade") == "websocket" {
		host.wsproxy.ServeHTTP(ctx.Resp, ctx.Req)
	} else {
		host.proxy.ServeHTTP(ctx.Resp, ctx.Req)
	}
	return RequestEnd
}

func (h *httpproxy) Hosts() utils.GroupRegexp {
	return h.allowhosts
}

func (hpx *httpproxy) GetHosts() []*HttpHost {
	return hpx.hosts
}

func (hpx *httpproxy) Insert(index int, id string, hosts []string, backend string, MaxConnsPerHost int, InsecureSkipVerify bool) error {
	buf := HttpHost{
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

	buf.proxy = &httputil.ReverseProxy{
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
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
		},
		FlushInterval: -1,
	}

	buf.wsproxy = &WebsocketProxy{
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
func insert(a []*HttpHost, index int, value *HttpHost) []*HttpHost {
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

func (hpx *httpproxy) Len() int {
	return len(hpx.hosts)
}

func (hpx *httpproxy) Reset() error {
	hpx.hosts = make([]*HttpHost, 0)
	hpx.buf.Refresh()

	return nil
}
