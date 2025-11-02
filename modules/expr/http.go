package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrhaoxx/OpenNG/config"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/utils"
	"github.com/rs/zerolog/log"
)

type httpexprbased struct {
	*vm.Program
}

func (e *httpexprbased) HandleHTTP(ctx *http.HttpCtx) http.Ret {
	output, err := expr.Run(e.Program, ctx)
	if err != nil {
		panic(err)
	}
	ret, _ := output.(bool)
	return http.Ret(ret)
}

func (e *httpexprbased) Hosts() utils.GroupRegexp {
	return nil
}

func init() {
	config.Register("expr::http", func(spec *config.ArgNode) (any, error) {
		expression := spec.ToString()
		log.Debug().
			Str("expression", expression).
			Msg("new http expr backend")

		program, err := expr.Compile(expression, expr.Env(&http.HttpCtx{}), expr.AsBool(), expr.Patch(MethodAsFuncPatcher{}),
			caller)

		if err != nil {
			return nil, err
		}
		return &httpexprbased{
			Program: program,
		}, nil
	}, config.Assert{
		Type:     "string",
		Required: true,
		Desc:     "expression-based HTTP backend",
	})
}
