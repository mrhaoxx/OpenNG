package expr

import (
	"github.com/expr-lang/expr"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/ngtcp"
	"github.com/mrhaoxx/OpenNG/pkg/ngexpr"
)

type TcpExprEnv struct {
	Tcp *ngtcp.Conn `expr:"tcp"`
}

type TcpExpr struct {
	cond ngexpr.IntExpr[TcpExprEnv]
}

func (e *TcpExpr) HandleTCP(ctx *ngtcp.Conn) ngtcp.Ret {
	output, err := expr.Run(e.cond.Program, TcpExprEnv{Tcp: ctx})
	if err != nil {
		panic(err)
	}
	ret, _ := output.(int)
	return ngtcp.Ret(ret)
}

type TcpExprConfig struct {
	Exp ngexpr.IntExpr[TcpExprEnv] `ng:"exp,required" desc:"expression to evaluate"`
}

func NewTCPExpr(cfg TcpExprConfig) (*TcpExpr, error) {
	return &TcpExpr{cond: cfg.Exp}, nil
}

func init() {
	ng.RegisterFunc("expr::tcp", NewTCPExpr)
}

var _ ngtcp.Service = (*TcpExpr)(nil)
