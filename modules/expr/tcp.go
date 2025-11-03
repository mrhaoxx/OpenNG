package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	"github.com/rs/zerolog/log"
)

type tcpexprbased struct {
	*vm.Program
}

func (e *tcpexprbased) HandleTCP(ctx *tcp.Conn) tcp.Ret {
	output, err := expr.Run(e.Program, ctx)
	if err != nil {
		panic(err)
	}
	ret, _ := output.(int)
	return tcp.Ret(ret)
}

func init() {
	ng.Register("expr::tcp", func(spec *ng.ArgNode) (any, error) {
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
	}, ng.Assert{
		Type:     "string",
		Required: true,
		Desc:     "expression-based TCP backend",
	})
}

var _ tcp.Service = (*tcpexprbased)(nil)
