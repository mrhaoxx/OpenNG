package expr

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	ngexpr "github.com/mrhaoxx/OpenNG/pkg/expr"
)

func init() {
	ng.Register("expr::tcp", ng.Assert{
		Type:     "string",
		Required: true,
		Desc:     "expression-based TCP backend",
	}, ng.Assert{
		Type: "ptr",
		Impls: []reflect.Type{
			ng.TypeOf[tcp.Service](),
		},
	}, func(spec *ng.ArgNode) (any, error) {
		expression := spec.ToString()

		obj := &ngexpr.TcpExpr{}

		err := obj.Compile(expression)
		if err != nil {
			return nil, err
		}
		return obj, nil
	})
}
