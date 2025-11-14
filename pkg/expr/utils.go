package expr

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
)

type MethodAsFuncPatcher struct{}

func (MethodAsFuncPatcher) Visit(node *ast.Node) {
	call, ok := (*node).(*ast.CallNode)
	if !ok {
		return
	}
	m, ok := call.Callee.(*ast.MemberNode)
	if !ok || !m.Method {
		return
	}
	var name string
	switch p := m.Property.(type) {
	case *ast.StringNode:
		name = p.Value
	case *ast.IdentifierNode:
		name = p.Value
	default:
		return
	}

	if t := m.Node.Type(); t != nil {
		if meth, ok := t.MethodByName(name); ok && meth.Type.NumOut() > 0 {
			return
		}
	}

	newCall := &ast.CallNode{
		Callee:    &ast.IdentifierNode{Value: "__call"},
		Arguments: append([]ast.Node{m.Node, &ast.StringNode{Value: name}}, call.Arguments...),
	}
	ast.Patch(node, newCall)

	(*node).SetType(reflect.TypeOf((*any)(nil)).Elem())
}

var caller = expr.Function(
	"__call",
	func(params ...any) (any, error) {
		recv := params[0]
		method := params[1].(string)
		args := params[2:]

		if recv == nil {
			return nil, nil
		}

		v := reflect.ValueOf(recv)
		m := v.MethodByName(method)
		if !m.IsValid() {
			return nil, fmt.Errorf("no such method: %s", method)
		}

		in := make([]reflect.Value, len(args))
		for i, a := range args {
			in[i] = reflect.ValueOf(a)
		}
		out := m.Call(in)

		switch len(out) {
		case 0:
			return true, nil
		case 1:
			return out[0].Interface(), nil
		default:
			if err, ok := out[len(out)-1].Interface().(error); ok && err != nil {
				return nil, err
			}
			return out[0].Interface(), nil
		}
	},
	new(func(any, string, ...any) any),
)

type ExprConfig struct {
	Exp  string `ng:"exp" desc:"expression to evaluate"`
	Vars any    `ng:"vars" desc:"custom variables to be used in the expression"`
}
