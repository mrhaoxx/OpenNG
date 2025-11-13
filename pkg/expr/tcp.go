package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
)

type TcpExpr struct {
	*vm.Program
}

func (e *TcpExpr) HandleTCP(ctx *ngtcp.Conn) ngtcp.Ret {
	output, err := expr.Run(e.Program, ctx)
	if err != nil {
		panic(err)
	}
	ret, _ := output.(int)
	return ngtcp.Ret(ret)
}

func (e *TcpExpr) Compile(expression string) error {
	program, err := expr.Compile(expression, expr.Env(&ngtcp.Conn{}), expr.AsInt(), expr.Patch(MethodAsFuncPatcher{}), caller)
	if err != nil {
		return err
	}
	e.Program = program
	return nil
}

var _ ngtcp.Service = (*TcpExpr)(nil)
