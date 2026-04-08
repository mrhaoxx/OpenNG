package nghttp

import (
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"golang.org/x/time/rate"
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

// ── http::rewrite ──

type RewriteService struct {
	pattern *regexp2.Regexp
	replace string
}

func (r *RewriteService) Hosts() groupexp.GroupRegexp { return nil }

func (r *RewriteService) HandleHTTP(ctx *HttpCtx) Ret {
	path := ctx.Req.URL.Path
	result, err := r.pattern.Replace(path, r.replace, -1, -1)
	if err != nil || result == path {
		return Continue
	}
	if result == "" || result[0] != '/' {
		result = "/" + result
	}
	ctx.Req.URL.Path = result
	return Continue
}

type RewriteConfig struct {
	Match   string `ng:"match,required" desc:"regex pattern to match against path"`
	Replace string `ng:"replace,required" desc:"replacement string ($1, $2 for capture groups)"`
}

func NewRewriteService(cfg RewriteConfig) (*RewriteService, error) {
	re, err := regexp2.Compile(cfg.Match, regexp2.RE2)
	if err != nil {
		return nil, err
	}
	return &RewriteService{pattern: re, replace: cfg.Replace}, nil
}

// ── http::ratelimit ──

type RateLimitService struct {
	global  *rate.Limiter            // used when by == "global"
	perIP   sync.Map                 // ip → *rate.Limiter
	rate    rate.Limit
	burst   int
	byIP    bool
	code    int
	message string
}

func (r *RateLimitService) Hosts() groupexp.GroupRegexp { return nil }

func (r *RateLimitService) HandleHTTP(ctx *HttpCtx) Ret {
	var limiter *rate.Limiter
	if r.byIP {
		val, _ := r.perIP.LoadOrStore(ctx.RemoteIP, rate.NewLimiter(r.rate, r.burst))
		limiter = val.(*rate.Limiter)
	} else {
		limiter = r.global
	}
	if !limiter.Allow() {
		ctx.Resp.WriteHeader(r.code)
		if r.message != "" {
			ctx.WriteString(r.message)
		}
		return RequestEnd
	}
	return Continue
}

type RateLimitConfig struct {
	Rate    float64 `ng:"rate,required" desc:"requests per second"`
	Burst   int     `ng:"burst" default:"10" desc:"max burst size"`
	By      string  `ng:"by" default:"ip" desc:"'ip' for per-IP limiting, 'global' for shared"`
	Code    int     `ng:"code" default:"429" desc:"HTTP status code when limited"`
	Message string  `ng:"message" desc:"response body when limited"`
}

func NewRateLimitService(cfg RateLimitConfig) (*RateLimitService, error) {
	r := &RateLimitService{
		rate:    rate.Limit(cfg.Rate),
		burst:   cfg.Burst,
		byIP:    cfg.By != "global",
		code:    cfg.Code,
		message: cfg.Message,
	}
	if r.burst == 0 {
		r.burst = 10
	}
	if r.code == 0 {
		r.code = http.StatusTooManyRequests
	}
	if !r.byIP {
		r.global = rate.NewLimiter(r.rate, r.burst)
	}
	return r, nil
}

// ── Registration ──

func init() {
	ng.RegisterFunc("http::redirect", NewRedirectService)
	ng.RegisterFunc("http::response", NewResponseService)
	ng.RegisterFunc("http::file", NewFileService)
	ng.RegisterFunc("http::proxy_pass", NewProxyPassService)
	ng.RegisterFunc("http::rewrite", NewRewriteService)
	ng.RegisterFunc("http::ratelimit", NewRateLimitService)
}
