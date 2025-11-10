package expr

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/http"
	ngexpr "github.com/mrhaoxx/OpenNG/pkg/expr"
)

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
			ng.TypeOf[http.Service](),
		},
	}, func(spec *ng.ArgNode) (any, error) {
		expression := spec.MustGet("exp").ToString()
		varsNode, err := spec.Get("vars")

		var vars any
		if err == nil {
			vars = varsNode.ToAny()
		}
		obj := &ngexpr.HttpExpr{
			Vars: vars,
		}
		err = obj.Compile(expression)
		if err != nil {
			return nil, err
		}
		return obj, nil
	})
}
