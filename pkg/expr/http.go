package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

type HttpExpr struct {
	*vm.Program
	Vars any
}

type httpExprEnv struct {
	Http *http.HttpCtx `expr:"http"`
	Vars any           `expr:"vars"`
}

func (e *HttpExpr) HandleHTTP(ctx *http.HttpCtx) http.Ret {

	output, err := expr.Run(e.Program, httpExprEnv{
		Http: ctx,
		Vars: e.Vars,
	})
	if err != nil {
		panic(err)
	}
	ret, _ := output.(bool)
	return http.Ret(ret)
}

func (e *HttpExpr) Hosts() groupexp.GroupRegexp {
	return nil
}

func (e *HttpExpr) Compile(expression string) error {
	program, err := expr.Compile(expression, expr.Env(httpExprEnv{
		Vars: e.Vars,
		Http: &http.HttpCtx{},
	}), expr.AsBool(), expr.Patch(MethodAsFuncPatcher{}), caller)
	if err != nil {
		return err
	}
	e.Program = program
	return nil
}

var _ http.Service = (*HttpExpr)(nil)
