package expr

import (
	"github.com/expr-lang/expr"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngexpr"
)

type HttpExpr struct {
	cond ngexpr.BoolExpr[HttpExprEnv]
	Vars any
}

type HttpExprEnv struct {
	Http     *nghttp.HttpCtx `expr:"http"`
	Vars     any             `expr:"vars"`
	Continue bool            `expr:"Continue"`
	End      bool            `expr:"End"`
}

func (e *HttpExpr) HandleHTTP(ctx *nghttp.HttpCtx) nghttp.Ret {
	output, err := expr.Run(e.cond.Program, HttpExprEnv{
		Http: ctx, Vars: e.Vars, Continue: true, End: false,
	})
	if err != nil {
		panic(err)
	}
	ret, _ := output.(bool)
	return nghttp.Ret(ret)
}

func (e *HttpExpr) Hosts() groupexp.GroupRegexp {
	return nil
}

type HttpExprConfig struct {
	Exp  ngexpr.BoolExpr[HttpExprEnv] `ng:"exp,required" desc:"expression to evaluate"`
	Vars any                          `ng:"vars" desc:"custom variables accessible as 'vars'"`
}

func NewHttpExpr(cfg HttpExprConfig) (*HttpExpr, error) {
	return &HttpExpr{cond: cfg.Exp, Vars: cfg.Vars}, nil
}

func init() {
	ng.RegisterFunc("expr::http", NewHttpExpr)
}

var _ nghttp.Service = (*HttpExpr)(nil)
