package expr

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/utils"
	"github.com/rs/zerolog/log"
)

type httpexprbased struct {
	*vm.Program
	Vars any
}

type httpExprEnv struct {
	Http *http.HttpCtx `expr:"http"`
	Vars any           `expr:"vars"`
}

func (e *httpexprbased) HandleHTTP(ctx *http.HttpCtx) http.Ret {

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

func (e *httpexprbased) Hosts() utils.GroupRegexp {
	return nil
}

func init() {
	netgate.Register("expr::http", func(spec *netgate.ArgNode) (any, error) {
		expression := spec.MustGet("exp").ToString()
		varsNode, err := spec.Get("vars")

		var vars any
		if err == nil {
			vars = varsNode.ToAny()
		}

		log.Debug().
			Str("expression", expression).
			Msg("new http expr backend")

		program, err := expr.Compile(expression, expr.Env(httpExprEnv{
			Vars: vars,
			Http: &http.HttpCtx{},
		}), expr.AsBool(), expr.Patch(MethodAsFuncPatcher{}), caller)

		if err != nil {
			return nil, err
		}
		return &httpexprbased{
			Program: program,
			Vars:    vars,
		}, nil
	}, netgate.Assert{
		Type:     "map",
		Required: true,
		Sub: netgate.AssertMap{
			"exp": {Type: "string", Required: true, Desc: "expression-based HTTP backend"},
			"vars": {
				Type: "map",
				Sub: netgate.AssertMap{
					"_": {Type: "any"},
				},
				Desc: "custom variables to be used in the expression",
			},
		},
	})
}
