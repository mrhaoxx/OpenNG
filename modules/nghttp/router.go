package nghttp

import (
	"strings"

	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

type Router struct {
	hosts    groupexp.GroupRegexp
	routes   []route
	fallback Service
}

type route struct {
	match     func(string) bool
	methods   map[string]bool
	service   Service
	stripPath string
}

func (r *Router) Hosts() groupexp.GroupRegexp { return r.hosts }

func (r *Router) HandleHTTP(ctx *HttpCtx) Ret {
	orig := ctx.Req.URL.Path
	for _, rt := range r.routes {
		if !rt.match(orig) || (rt.methods != nil && !rt.methods[ctx.Req.Method]) {
			continue
		}
		if rt.stripPath != "" {
			p := strings.TrimPrefix(orig, rt.stripPath)
			if p == "" || p[0] != '/' {
				p = "/" + p
			}
			ctx.Req.URL.Path = p
		}
		if rt.service.HandleHTTP(ctx) == RequestEnd {
			return RequestEnd
		}
		ctx.Req.URL.Path = orig
	}
	if r.fallback != nil {
		return r.fallback.HandleHTTP(ctx)
	}
	return Continue
}

type RouteConfig struct {
	Path        string   `ng:"path,required" desc:"prefix '/api/', exact '= /health', regex '~ ^/u/\\d+'"`
	Method      []string `ng:"method" desc:"allowed methods (empty = all)"`
	Service     Service  `ng:"service,required" desc:"target service"`
	StripPrefix bool     `ng:"strip_prefix" desc:"strip matched prefix"`
}

type RouterConfig struct {
	Hosts    ng.HostnameSlice `ng:"hosts" default:"[*]" desc:"hostnames to handle"`
	Routes   []RouteConfig    `ng:"routes,required" desc:"route rules, matched in order"`
	Fallback Service          `ng:"fallback" desc:"default when no route matches"`
}

func NewRouter(cfg RouterConfig) (*Router, error) {
	r := &Router{hosts: cfg.Hosts.GroupRegexp(), fallback: cfg.Fallback}
	for _, rc := range cfg.Routes {
		rt := route{match: parsePath(rc.Path), service: rc.Service}
		if rc.StripPrefix {
			p := strings.TrimSpace(rc.Path)
			if !strings.HasPrefix(p, "= ") && !strings.HasPrefix(p, "~ ") {
				rt.stripPath = p
			}
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

func parsePath(p string) func(string) bool {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "= ") {
		exact := p[2:]
		return func(s string) bool { return s == exact }
	}
	if strings.HasPrefix(p, "~ ") {
		re := regexp2.MustCompile(p[2:], regexp2.RE2)
		return func(s string) bool { ok, _ := re.MatchString(s); return ok }
	}
	return func(s string) bool { return strings.HasPrefix(s, p) }
}

func init() { ng.RegisterFunc("http::router", NewRouter) }
