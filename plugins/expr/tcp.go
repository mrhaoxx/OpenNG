package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/ui"
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
	ui.Register("expr::tcp", func(spec *ui.ArgNode) (any, error) {
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
	}, ui.Assert{
		Type:     "string",
		Required: true,
		Desc:     "expression-based TCP backend",
	})
}
