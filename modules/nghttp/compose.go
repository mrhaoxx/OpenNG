package nghttp

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

// ── http::chain — sequential service pipeline ──

type Chain struct {
	hosts    ng.HostnameSlice
	services []Service
}

func (c *Chain) Hosts() groupexp.GroupRegexp { return c.hosts.GroupRegexp() }

func (c *Chain) HandleHTTP(ctx *HttpCtx) Ret {
	for _, svc := range c.services {
		if svc.HandleHTTP(ctx) == RequestEnd {
			return RequestEnd
		}
	}
	return Continue
}

type ChainConfig struct {
	Hosts    ng.HostnameSlice `ng:"hosts" default:"[*]" desc:"hostnames to handle"`
	Services []Service        `ng:"services,required" desc:"services to execute in order"`
}

func NewChain(cfg ChainConfig) (*Chain, error) {
	return &Chain{hosts: cfg.Hosts, services: cfg.Services}, nil
}

// ── http::branch — conditional dispatch via expr ──

type condEnv struct {
	Http *HttpCtx `expr:"http"`
}

type Branch struct {
	hosts     ng.HostnameSlice
	cond      *vm.Program
	then      Service
	otherwise Service
}

func (b *Branch) Hosts() groupexp.GroupRegexp { return b.hosts.GroupRegexp() }

func (b *Branch) HandleHTTP(ctx *HttpCtx) Ret {
	result, err := expr.Run(b.cond, condEnv{Http: ctx})
	if err != nil {
		ctx.Resp.ErrorPage(500, "branch condition error: "+err.Error())
		return RequestEnd
	}
	matched, _ := result.(bool)
	if matched {
		if b.then != nil {
			return b.then.HandleHTTP(ctx)
		}
		return Continue
	}
	if b.otherwise != nil {
		return b.otherwise.HandleHTTP(ctx)
	}
	return Continue
}

type BranchConfig struct {
	Hosts     ng.HostnameSlice `ng:"hosts" default:"[*]" desc:"hostnames to handle"`
	Condition string           `ng:"condition,required" desc:"expr expression evaluating to bool"`
	Then      Service          `ng:"then,required" desc:"service when condition is true"`
	Else      Service          `ng:"else" desc:"service when condition is false"`
}

func NewBranch(cfg BranchConfig) (*Branch, error) {
	program, err := expr.Compile(cfg.Condition,
		expr.Env(condEnv{Http: &HttpCtx{}}),
		expr.AsBool(),
	)
	if err != nil {
		return nil, err
	}
	return &Branch{hosts: cfg.Hosts, cond: program, then: cfg.Then, otherwise: cfg.Else}, nil
}

func init() {
	ng.RegisterFunc("http::chain", NewChain)
	ng.RegisterFunc("http::branch", NewBranch)
}
