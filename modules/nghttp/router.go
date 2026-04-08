package nghttp

import (
	"net/http"
	"strings"

	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

// Router implements path-based routing, similar to nginx location blocks.
// It matches requests by path (prefix, exact, or regex) and optionally by method,
// then dispatches to a target service, or returns a redirect.
type Router struct {
	hosts    groupexp.GroupRegexp
	routes   []route
	fallback Service
}

type route struct {
	matcher    pathMatcher
	methods    map[string]bool // nil = all methods
	service    Service         // target service (nil if redirect)
	redirect   string          // redirect URL (empty if service)
	code       int             // redirect status code
	stripPath  string          // prefix to strip before forwarding
}

type pathMatcher interface {
	match(path string) bool
}

type prefixMatcher string

func (p prefixMatcher) match(path string) bool {
	return strings.HasPrefix(path, string(p))
}

type exactMatcher string

func (e exactMatcher) match(path string) bool {
	return path == string(e)
}

type regexMatcher struct {
	re *regexp2.Regexp
}

func (r *regexMatcher) match(path string) bool {
	ok, _ := r.re.MatchString(path)
	return ok
}

func (r *Router) Hosts() groupexp.GroupRegexp {
	return r.hosts
}

func (r *Router) HandleHTTP(ctx *HttpCtx) Ret {
	path := ctx.Req.URL.Path
	method := ctx.Req.Method

	for _, rt := range r.routes {
		if !rt.matcher.match(path) {
			continue
		}
		if rt.methods != nil && !rt.methods[method] {
			continue
		}

		// Redirect
		if rt.redirect != "" {
			code := rt.code
			if code == 0 {
				code = http.StatusFound
			}
			ctx.Resp.Header().Set("Location", rt.redirect)
			ctx.Resp.WriteHeader(code)
			return RequestEnd
		}

		// Strip prefix
		if rt.stripPath != "" {
			ctx.Req.URL.Path = strings.TrimPrefix(path, rt.stripPath)
			if ctx.Req.URL.Path == "" || ctx.Req.URL.Path[0] != '/' {
				ctx.Req.URL.Path = "/" + ctx.Req.URL.Path
			}
		}

		// Dispatch to service
		if rt.service != nil {
			return rt.service.HandleHTTP(ctx)
		}
	}

	// Fallback
	if r.fallback != nil {
		return r.fallback.HandleHTTP(ctx)
	}

	ctx.Resp.ErrorPage(StatusNotFound, "No matching route for "+path)
	return RequestEnd
}

// --- Config & Registration ---

type RouteConfig struct {
	Path        string   `ng:"path,required" desc:"path pattern: prefix '/api/', exact '= /health', regex '~ ^/user/\\d+'"`
	Method      []string `ng:"method" desc:"allowed HTTP methods (empty = all)"`
	Service     Service  `ng:"service" desc:"target service to forward to"`
	Redirect    string   `ng:"redirect" desc:"redirect URL (mutually exclusive with service)"`
	Code        int      `ng:"code" desc:"redirect status code (default 302)"`
	StripPrefix bool     `ng:"strip_prefix" desc:"strip the matched path prefix before forwarding"`
}

type RouterConfig struct {
	Hosts    ng.HostnameSlice `ng:"hosts" default:"[*]" desc:"hostnames this router handles"`
	Routes   []RouteConfig    `ng:"routes,required" desc:"route rules, matched in order"`
	Fallback Service          `ng:"fallback" desc:"fallback service when no route matches"`
}

func parsePath(pattern string) pathMatcher {
	pattern = strings.TrimSpace(pattern)
	if strings.HasPrefix(pattern, "= ") {
		return exactMatcher(pattern[2:])
	}
	if strings.HasPrefix(pattern, "~ ") {
		re := regexp2.MustCompile(pattern[2:], regexp2.RE2)
		return &regexMatcher{re: re}
	}
	// Default: prefix match
	return prefixMatcher(pattern)
}

func NewRouter(cfg RouterConfig) (*Router, error) {
	r := &Router{
		hosts:    cfg.Hosts.GroupRegexp(),
		fallback: cfg.Fallback,
	}

	for _, rc := range cfg.Routes {
		rt := route{
			matcher:  parsePath(rc.Path),
			redirect: rc.Redirect,
			code:     rc.Code,
			service:  rc.Service,
		}
		if rc.StripPrefix && !strings.HasPrefix(rc.Path, "= ") && !strings.HasPrefix(rc.Path, "~ ") {
			rt.stripPath = strings.TrimSpace(rc.Path)
		}
		if len(rc.Method) > 0 {
			rt.methods = make(map[string]bool, len(rc.Method))
			for _, m := range rc.Method {
				rt.methods[strings.ToUpper(m)] = true
			}
		}
		r.routes = append(r.routes, rt)
	}

	return r, nil
}

func init() {
	ng.RegisterFunc("http::router", NewRouter)
}
