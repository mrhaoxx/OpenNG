package nghttp

import (
	"io/fs"
	"net/http"
	"strings"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

// ── http::redirect ──

type RedirectService struct {
	url  string
	code int
}

func (r *RedirectService) Hosts() groupexp.GroupRegexp { return nil }

func (r *RedirectService) HandleHTTP(ctx *HttpCtx) Ret {
	target := r.url
	// Support ${path} and ${query} placeholders
	target = strings.ReplaceAll(target, "${path}", ctx.Req.URL.Path)
	target = strings.ReplaceAll(target, "${query}", ctx.Req.URL.RawQuery)
	target = strings.ReplaceAll(target, "${host}", ctx.Req.Host)
	ctx.Resp.Header().Set("Location", target)
	ctx.Resp.WriteHeader(r.code)
	return RequestEnd
}

type RedirectConfig struct {
	URL  string `ng:"url,required" desc:"redirect target URL (supports ${path}, ${query}, ${host})"`
	Code int    `ng:"code" default:"302" desc:"HTTP status code (301, 302, 307, 308)"`
}

func NewRedirectService(cfg RedirectConfig) (*RedirectService, error) {
	code := cfg.Code
	if code == 0 {
		code = http.StatusFound
	}
	return &RedirectService{url: cfg.URL, code: code}, nil
}

// ── http::response ──

type ResponseService struct {
	code    int
	body    string
	headers map[string]string
}

func (r *ResponseService) Hosts() groupexp.GroupRegexp { return nil }

func (r *ResponseService) HandleHTTP(ctx *HttpCtx) Ret {
	for k, v := range r.headers {
		ctx.Resp.Header().Set(k, v)
	}
	ctx.Resp.WriteHeader(r.code)
	if r.body != "" {
		ctx.WriteString(r.body)
	}
	return RequestEnd
}

type ResponseConfig struct {
	Code    int               `ng:"code" default:"200" desc:"HTTP status code"`
	Body    string            `ng:"body" desc:"response body"`
	Headers map[string]string `ng:"headers" desc:"response headers"`
}

func NewResponseService(cfg ResponseConfig) (*ResponseService, error) {
	code := cfg.Code
	if code == 0 {
		code = http.StatusOK
	}
	return &ResponseService{code: code, body: cfg.Body, headers: cfg.Headers}, nil
}

// ── http::file ──

type FileService struct {
	root    http.FileSystem
	handler http.Handler
}

func (f *FileService) Hosts() groupexp.GroupRegexp { return nil }

func (f *FileService) HandleHTTP(ctx *HttpCtx) Ret {
	f.handler.ServeHTTP(ctx.Resp, ctx.Req)
	return RequestEnd
}

type FileConfig struct {
	Root string `ng:"root,required" desc:"root directory to serve files from"`
}

func NewFileService(cfg FileConfig) (*FileService, error) {
	root := http.Dir(cfg.Root)
	return &FileService{
		root:    root,
		handler: http.FileServer(root),
	}, nil
}

// ── http::proxy_pass ──

type ProxyPassService struct {
	proxy *ReverseProxy
}

func (p *ProxyPassService) Hosts() groupexp.GroupRegexp { return nil }

func (p *ProxyPassService) HandleHTTP(ctx *HttpCtx) Ret {
	return p.proxy.HandleHTTP(ctx)
}

type ProxyPassConfig struct {
	Backend         ngnet.URL `ng:"backend,required" default:"sys%tcp://" desc:"backend URL to proxy to"`
	TlsSkipVerify   bool     `ng:"tls_skip_verify" desc:"skip TLS certificate verification"`
	MaxConnsPerHost  int      `ng:"max_conns_per_host" desc:"max concurrent connections to backend"`
	BypassEncoding   bool     `ng:"bypass_encoding" desc:"let backend handle encoding"`
}

func NewProxyPassService(cfg ProxyPassConfig) (*ProxyPassService, error) {
	proxier := NewHTTPProxier(nil)
	backend := cfg.Backend
	if err := proxier.Insert(0, "default", nil, &backend, cfg.MaxConnsPerHost, cfg.TlsSkipVerify, cfg.BypassEncoding); err != nil {
		return nil, err
	}
	return &ProxyPassService{proxy: proxier}, nil
}

// ── http::filesystem (embed-compatible) ──

type FSService struct {
	handler http.Handler
}

func (f *FSService) Hosts() groupexp.GroupRegexp { return nil }

func (f *FSService) HandleHTTP(ctx *HttpCtx) Ret {
	f.handler.ServeHTTP(ctx.Resp, ctx.Req)
	return RequestEnd
}

func NewFSServiceFromFS(fsys fs.FS) *FSService {
	return &FSService{handler: http.FileServer(http.FS(fsys))}
}

// ── Registration ──

func init() {
	ng.RegisterFunc("http::redirect", NewRedirectService)
	ng.RegisterFunc("http::response", NewResponseService)
	ng.RegisterFunc("http::file", NewFileService)
	ng.RegisterFunc("http::proxy_pass", NewProxyPassService)
}
