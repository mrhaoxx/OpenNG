// Package ngexpr provides typed expr expression types for use in config structs.
// BoolExpr[E] and IntExpr[E] carry their environment type via generics,
// enabling automatic schema generation with autocomplete info.
package ngexpr

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/vm"

	ng "github.com/mrhaoxx/OpenNG"
)

// ── Expr types ──

func compileExpr[E any](source string, opts ...expr.Option) (*vm.Program, error) {
	var zero E
	base := []expr.Option{
		expr.Env(zero),
		expr.Patch(MethodAsFuncPatcher{}),
		Caller,
	}
	return expr.Compile(source, append(base, opts...)...)
}

// BoolExpr is a compiled expr expression that evaluates to bool.
// E defines the expression environment; its exported fields and methods
// are reflected to generate autocomplete info in the config schema.
type BoolExpr[E any] struct {
	*vm.Program
}

func (*BoolExpr[E]) Assert() ng.Assert {
	return ng.Assert{
		Type:    "expr",
		ExprEnv: ReflectEnv(reflect.TypeFor[E]()),
		ExprCheck: func(source string) error {
			_, err := compileExpr[E](source, expr.AsBool())
			return err
		},
	}
}

func (e *BoolExpr[E]) UnmarshalArgNode(node *ng.ArgNode) error {
	p, err := compileExpr[E](node.ToString(), expr.AsBool())
	if err != nil {
		return err
	}
	e.Program = p
	return nil
}

// IntExpr is a compiled expr expression that evaluates to int.
type IntExpr[E any] struct {
	*vm.Program
}

func (*IntExpr[E]) Assert() ng.Assert {
	return ng.Assert{
		Type:    "expr",
		ExprEnv: ReflectEnv(reflect.TypeFor[E]()),
		ExprCheck: func(source string) error {
			_, err := compileExpr[E](source, expr.AsInt())
			return err
		},
	}
}

func (e *IntExpr[E]) UnmarshalArgNode(node *ng.ArgNode) error {
	p, err := compileExpr[E](node.ToString(), expr.AsInt())
	if err != nil {
		return err
	}
	e.Program = p
	return nil
}

// ── MethodAsFuncPatcher ──

// MethodAsFuncPatcher enables calling void-returning methods in expr.
// It converts obj.Method(args) to __call(obj, "Method", args...) when
// the method has no return value (which expr normally forbids).
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

// Caller is the __call builtin function for MethodAsFuncPatcher.
var Caller = expr.Function(
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
