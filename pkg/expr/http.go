package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/nghttp"
)

type HttpExpr struct {
	*vm.Program
	Vars any
}

type httpExprEnv struct {
	Http *nghttp.HttpCtx `expr:"http"`
	Vars any             `expr:"vars"`
}

func (e *HttpExpr) HandleHTTP(ctx *nghttp.HttpCtx) nghttp.Ret {

	output, err := expr.Run(e.Program, httpExprEnv{
		Http: ctx,
		Vars: e.Vars,
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

func (e *HttpExpr) Compile(expression string) error {
	program, err := expr.Compile(expression, expr.Env(httpExprEnv{
		Vars: e.Vars,
		Http: &nghttp.HttpCtx{},
	}), expr.AsBool(), expr.Patch(MethodAsFuncPatcher{}), caller)
	if err != nil {
		return err
	}
	e.Program = program
	return nil
}

func NewHttpExpr(cfg ExprConfig) (*HttpExpr, error) {
	obj := &HttpExpr{
		Vars: cfg.Vars,
	}
	err := obj.Compile(cfg.Exp)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

var _ nghttp.Service = (*HttpExpr)(nil)
