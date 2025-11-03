package http

import (
	"context"
	"crypto/tls"
	"errors"
	gonet "net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mrhaoxx/OpenNG/modules/dns"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/lookup"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"

	zlog "github.com/rs/zerolog/log"
)

type HttpHost struct {
	Id                 string
	ServerName         groupexp.GroupRegexp
	Backend            *ngnet.URL
	InsecureSkipVerify bool
	MaxConnsPerHost    int
	BypassEncoding     bool
	Underlying         ngnet.Interface

	proxy   *httputil.ReverseProxy
	wsproxy *WebsocketProxy
}

func (h *HttpHost) Init() {

	if h.Underlying == nil {
		panic("underlying interface is nil")
	}

	var HTTPTlsConfig = tls.Config{
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       _my_cipher_suit,
		InsecureSkipVerify: h.InsecureSkipVerify,
	}

	var WSTlsConfig = tls.Config{
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       _my_cipher_suit,
		InsecureSkipVerify: h.InsecureSkipVerify,
	}

	hostport, _ := hostPortNoPort(&h.Backend.URL)

	var issecure = h.Backend.URL.Scheme == "https"

	dialer := func(ctx context.Context, network, addr string) (gonet.Conn, error) {
		return h.Underlying.DialContext(ctx, network, hostport)
	}

	h.proxy = &httputil.ReverseProxy{
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {
			rw.(*NgResponseWriter).ErrorPage(http.StatusBadGateway, "Bad Gateway")
			zlog.Error().
				Str("type", "http/reverseproxy").
				Str("host", r.Host).
				Str("id", h.Id).
				Str("conn", rw.(*NgResponseWriter).ctx.conn.Id).
				Str("reqid", rw.(*NgResponseWriter).ctx.Id).
				Str("error", e.Error()).
				Msg("")
		},
		Transport: &http.Transport{
			TLSClientConfig:       &HTTPTlsConfig,
			DialContext:           dialer,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			IdleConnTimeout:       0,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxConnsPerHost:       h.MaxConnsPerHost,
		},
		Director: func(r *http.Request) {
			r.URL.Scheme = h.Backend.URL.Scheme
			r.URL.Host = h.Backend.URL.Host

			delete(r.Header, "X-Forwarded-For")
			r.Header.Add("X-Forwarded-Host", r.Host)
			if r.TLS == nil {
				r.Header.Set("X-Forwarded-Proto", "http")
			} else {
				r.Header.Set("X-Forwarded-Proto", "https")
			}
		},
		FlushInterval: -1,
	}

	h.wsproxy = &WebsocketProxy{
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
			if issecure {
				u_ws.Scheme = "wss"
			}
			return u_ws
		},
		Dialer: &websocket.Dialer{
			TLSClientConfig: &WSTlsConfig,
			NetDialContext:  dialer,
		},
	}
}

type ReverseProxy struct {
	hosts []*HttpHost

	buf *lookup.BufferedLookup[*HttpHost]

	allowhosts groupexp.GroupRegexp
}

func (h *ReverseProxy) HandleHTTPCgi(ctx *HttpCtx, path string) Ret {
	_host := h.buf.Lookup(ctx.Req.Host)
	var id string
	if _host != nil {
		id = _host.Id
	} else {
		id = "nohit"
	}

	ctx.WriteString("id: " + id + "\n")
	return RequestEnd
}
func (*ReverseProxy) CgiPaths() groupexp.GroupRegexp {
	return regexpforproxy
}

func NewHTTPProxier(allowedhosts []string) *ReverseProxy {
	hpx := &ReverseProxy{
		hosts:      make([]*HttpHost, 0),
		allowhosts: groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(allowedhosts)),
	}

	hpx.buf = lookup.NewBufferedLookup(func(host string) *HttpHost {
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

func (h *ReverseProxy) HandleHTTP(ctx *HttpCtx) Ret {
	_host := h.buf.Lookup(ctx.Req.Host)
	if _host == nil {
		return Continue
	}

	host := _host

	defer func() {
		recover()
	}()

	if host.BypassEncoding {
		ctx.Resp.BypassEncoding()
	}

	if ctx.Req.Header.Get("Upgrade") == "websocket" {
		host.wsproxy.ServeHTTP(ctx.Resp, ctx.Req)
	} else {
		host.proxy.ServeHTTP(ctx.Resp, ctx.Req)
	}
	return RequestEnd
}

func (h *ReverseProxy) Hosts() groupexp.GroupRegexp {
	return h.allowhosts
}

func (hpx *ReverseProxy) GetHosts() []*HttpHost {
	return hpx.hosts
}

func (hpx *ReverseProxy) Insert(index int, id string, hosts []string, backend *ngnet.URL, MaxConnsPerHost int, InsecureSkipVerify bool, BypassEncoding bool) error {
	buf := HttpHost{
		Id:                 id,
		ServerName:         groupexp.MustCompileRegexp(dns.Dnsnames2Regexps(hosts)),
		Backend:            backend,
		MaxConnsPerHost:    MaxConnsPerHost,
		InsecureSkipVerify: InsecureSkipVerify,
		Underlying:         backend.Underlying,
		BypassEncoding:     BypassEncoding,
	}
	buf.Init()

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

var _ Service = (*ReverseProxy)(nil)
