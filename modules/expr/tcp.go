package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	ngmodules "github.com/mrhaoxx/OpenNG/modules"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	"github.com/rs/zerolog/log"
)

type tcpexprbased struct {
	*vm.Program
}

func (e *tcpexprbased) Handle(ctx *tcp.Conn) tcp.SerRet {
	output, err := expr.Run(e.Program, ctx)
	if err != nil {
		panic(err)
	}
	ret, _ := output.(int)
	return tcp.SerRet(ret)
}

func init() {
	ngmodules.Register("expr::tcp", func(spec *ngmodules.ArgNode) (any, error) {
		expression := spec.ToString()
		log.Debug().
			Str("expression", expression).
			Msg("new tcp expr backend")

		program, err := expr.Compile(expression, expr.Env(&tcp.Conn{}), expr.AsInt(), expr.Patch(MethodAsFuncPatcher{}),
			caller)

		if err != nil {
			return nil, err
		}
		return &tcpexprbased{
			Program: program,
		}, nil
	}, ngmodules.Assert{
		Type:     "string",
		Required: true,
		Desc:     "expression-based TCP backend",
	})
}
