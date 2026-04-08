package nghttp

import (
	"github.com/expr-lang/expr"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngexpr"
)

// Chain and Branch return nil Hosts() — host matching is done by the
// midware's per-entry config, so these services don't need their own.

// ── http::chain — sequential service pipeline ──

type Chain struct {
	services []Service
}

func (c *Chain) Hosts() groupexp.GroupRegexp { return nil }

func (c *Chain) HandleHTTP(ctx *HttpCtx) Ret {
	for _, svc := range c.services {
		if svc.HandleHTTP(ctx) == RequestEnd {
			return RequestEnd
		}
	}
	return Continue
}

type ChainConfig struct {
	Services []Service `ng:"services,required" desc:"services to execute in order"`
}

func NewChain(cfg ChainConfig) (*Chain, error) {
	return &Chain{services: cfg.Services}, nil
}

// ── http::branch — conditional dispatch via expr ──

type CondEnv struct {
	Http     *HttpCtx `expr:"http"`
	Continue bool     `expr:"Continue"` // true — pass to next service
	End      bool     `expr:"End"`      // false — stop processing
}

type Branch struct {
	cond      ngexpr.BoolExpr[CondEnv]
	then      Service
	otherwise Service
}

func (b *Branch) Hosts() groupexp.GroupRegexp { return nil }

func (b *Branch) HandleHTTP(ctx *HttpCtx) Ret {
	result, err := expr.Run(b.cond.Program, CondEnv{Http: ctx, Continue: true, End: false})
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
	Condition ngexpr.BoolExpr[CondEnv] `ng:"condition,required" desc:"expr expression evaluating to bool"`
	Then      Service                  `ng:"then,required" desc:"service when condition is true"`
	Else      Service                  `ng:"else" desc:"service when condition is false"`
}

func NewBranch(cfg BranchConfig) (*Branch, error) {
	return &Branch{cond: cfg.Condition, then: cfg.Then, otherwise: cfg.Else}, nil
}

func init() {
	ng.RegisterFunc("http::chain", NewChain)
	ng.RegisterFunc("http::branch", NewBranch)
}
