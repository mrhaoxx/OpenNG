package ngexpr

import (
	"reflect"
	"strings"
)

// EnvNode describes a field or method available in an expr environment.
type EnvNode struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Kind     string    `json:"kind"` // "field" or "method"
	Children []EnvNode `json:"children,omitempty"`
}

const maxDepth = 4
const methodDepth = 3 // only include methods for the first N levels

// ReflectEnv extracts the field/method tree from a Go type for schema generation.
func ReflectEnv(t reflect.Type) []EnvNode {
	visited := map[reflect.Type]bool{}
	return structMembers(t, visited, 0)
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

// structMembers returns fields + methods of a struct type.
// Methods are only included when depth < methodDepth to keep output compact.
func structMembers(t reflect.Type, visited map[reflect.Type]bool, depth int) []EnvNode {
	if depth > maxDepth {
		return nil
	}
	dt := deref(t)
	if dt.Kind() != reflect.Struct {
		return nil
	}
	if visited[dt] {
		return nil
	}
	visited[dt] = true
	defer delete(visited, dt)

	var nodes []EnvNode

	// exported fields
	for i := 0; i < dt.NumField(); i++ {
		f := dt.Field(i)
		if !f.IsExported() {
			continue
		}

		name := f.Name
		if tag := f.Tag.Get("expr"); tag != "" {
			name = tag
		}

		node := EnvNode{
			Name:     name,
			Type:     typeName(f.Type),
			Kind:     "field",
			Children: structMembers(f.Type, visited, depth+1),
		}
		nodes = append(nodes, node)
	}

	// methods — only at shallow depths
	if depth < methodDepth {
		pt := reflect.PointerTo(dt)
		for i := 0; i < pt.NumMethod(); i++ {
			m := pt.Method(i)
			if m.PkgPath != "" || isSkippedMethod(m.Name) {
				continue
			}
			nodes = append(nodes, EnvNode{
				Name: m.Name,
				Type: methodSignature(m.Type),
				Kind: "method",
			})
		}
	}

	return nodes
}

func methodSignature(t reflect.Type) string {
	var b strings.Builder
	b.WriteString("(")
	// skip receiver (index 0)
	for i := 1; i < t.NumIn(); i++ {
		if i > 1 {
			b.WriteString(", ")
		}
		b.WriteString(typeName(t.In(i)))
	}
	b.WriteString(")")
	if t.NumOut() > 0 {
		b.WriteString(" ")
		if t.NumOut() == 1 {
			b.WriteString(typeName(t.Out(0)))
		} else {
			b.WriteString("(")
			for i := 0; i < t.NumOut(); i++ {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(typeName(t.Out(i)))
			}
			b.WriteString(")")
		}
	}
	return b.String()
}

func typeName(t reflect.Type) string {
	if t == nil {
		return "any"
	}
	switch t.Kind() {
	case reflect.Ptr:
		return "*" + typeName(t.Elem())
	case reflect.Slice:
		return "[]" + typeName(t.Elem())
	case reflect.Map:
		return "map[" + typeName(t.Key()) + "]" + typeName(t.Elem())
	case reflect.Interface:
		if t.NumMethod() == 0 {
			return "any"
		}
		return t.String()
	default:
		return t.String()
	}
}

func isSkippedMethod(name string) bool {
	switch name {
	case "Assert", "UnmarshalArgNode", "MarshalJSON", "UnmarshalJSON",
		"String", "GoString", "Format":
		return true
	}
	return false
}
