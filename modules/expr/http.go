package expr

import (
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
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

func (e *httpexprbased) Hosts() groupexp.GroupRegexp {
	return nil
}

func init() {
	ng.Register("expr::http", ng.Assert{
		Type:     "map",
		Required: true,
		Sub: ng.AssertMap{
			"exp": {Type: "string", Required: true, Desc: "expression-based HTTP backend"},
			"vars": {
				Type: "map",
				Sub: ng.AssertMap{
					"_": {Type: "any"},
				},
				Desc: "custom variables to be used in the expression",
			},
		},
	}, ng.Assert{
		Type: "ptr",
		Impls: []reflect.Type{
			ng.Iface[http.Service](),
		},
	}, func(spec *ng.ArgNode) (any, error) {
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
	})
}

var _ http.Service = (*httpexprbased)(nil)
