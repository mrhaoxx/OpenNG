package netgate

import (
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/mrhaoxx/OpenNG/net"
)

//go:embed cmd/NetGATE.svg
var logo_svg []byte

func Logo() []byte {
	return logo_svg
}

const (
	ServerSign = "OpenNG"
)

var refs_assertions = map[string]Assert{}

var refs = map[string]Inst{}

func Register(name string, inst Inst, assert Assert) {
	refs[name] = inst
	refs_assertions[name] = assert
}

func Registry() map[string]Inst {
	return refs
}

func AssertionsRegistry() map[string]Assert {
	return refs_assertions
}

type Inst func(*ArgNode) (any, error)

type AssertMap map[string]Assert

type Assert struct {
	Type     string
	Required bool
	Forced   bool
	Sub      AssertMap

	Default any

	Enum         []any
	AllowNonEnum bool
	Desc         string
}

type ArgNode struct {
	Type  string
	Value any
}

func (node *ArgNode) MustGet(path string) *ArgNode {
	v, _ := node.Get(path)
	return v
}

func (node *ArgNode) ToStringList() []string {
	if node == nil {
		return nil
	}

	if node.Type != "list" {
		return nil
	}
	var ret []string
	for _, v := range node.ToList() {
		if v.Value == nil {
			ret = append(ret, "")
		} else {
			ret = append(ret, v.Value.(string))
		}
	}
	return ret
}

func (node *ArgNode) ToString() string {
	if node == nil {
		return ""
	}

	return node.Value.(string)
}

func (node *ArgNode) ToInt() int {
	if node == nil {
		return 0
	}
	if node.Type != "int" {
		return 0
	}
	return node.Value.(int)
}

func (node *ArgNode) ToBool() bool {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "bool" {
		return false
	}
	return node.Value.(bool)
}

func (node *ArgNode) ToList() []*ArgNode {
	if node == nil {
		return nil
	}

	if node.Type != "list" {
		return nil
	}
	return node.Value.([]*ArgNode)
}

func (node *ArgNode) ToMap() map[string]*ArgNode {
	if node == nil {
		panic("nil node")
	}

	if node.Type != "map" {
		return nil
	}
	return node.Value.(map[string]*ArgNode)
}

func (node *ArgNode) ToDuration() time.Duration {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "duration" {
		return 0
	}

	return node.Value.(time.Duration)
}

func (node *ArgNode) ToURL() *net.URL {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "url" {
		return nil
	}

	return node.Value.(*net.URL)
}

func (node *ArgNode) ToAny() any {
	if node == nil {
		return nil
	}
	switch node.Type {
	case "map":
		ret := map[string]any{}
		for k, v := range node.Value.(map[string]*ArgNode) {
			ret[k] = v.ToAny()
		}
		return ret

	case "list":
		ret := make([]any, len(node.ToList()))
		for i, v := range node.ToList() {
			ret[i] = v.ToAny()
		}
		return ret
	default:
		return node.Value
	}
}

func (m *ArgNode) FromAny(raw any) error {
	switch raw := raw.(type) {
	case nil:
		m.Type = "null"
		m.Value = nil
		return nil
	case string:
		switch {
		case strings.HasPrefix(raw, "$dref{"):
			{
				if strings.HasSuffix(raw, "...") {
					m.Type = "dref..."
					m.Value = raw[len("$dref{") : len(raw)-4]
					return nil
				}
				m.Type = "dref"
				m.Value = raw[len("$dref{") : len(raw)-1]
				return nil
			}
		default:
			m.Type = "string"
			m.Value = raw
			return nil
		}
	case int:
		m.Type = "int"
		m.Value = raw
		return nil
	case float64:
		m.Type = "float"
		m.Value = raw
		return nil
	case bool:
		m.Type = "bool"
		m.Value = raw
		return nil
	case map[string]any:
		subnodes := make(map[string]*ArgNode)
		for k, v := range raw {
			subnode := &ArgNode{}
			err := subnode.FromAny(v)
			if err != nil {
				return err
			}
			subnodes[k] = subnode
		}
		m.Type = "map"
		m.Value = subnodes
		return nil
	case []interface{}:
		subnodes := make([]*ArgNode, len(raw))
		for i, v := range raw {
			subnode := &ArgNode{}
			err := subnode.FromAny(v)
			if err != nil {
				return err
			}
			subnodes[i] = subnode
		}
		m.Type = "list"
		m.Value = subnodes
		return nil
	default:
		return fmt.Errorf("unsupported type: %T", raw)
	}
}

func (node *ArgNode) Get(path string) (*ArgNode, error) {
	if path == "" {
		return node, nil
	}

	if node == nil {
		return nil, fmt.Errorf("path not found")
	}

	switch node.Type {
	case "map":
		access := strings.Split(path, ".")

		rh := access[0]
		if strings.HasSuffix(access[0], "]") {
			rh = rh[:strings.LastIndex(access[0], "[")]
			access[0] = access[0][len(rh):]
		} else {
			access = access[1:]
		}

		v, ok := node.ToMap()[rh]
		if !ok {
			return nil, fmt.Errorf("path not found")
		}
		return v.Get(strings.Join(access, "."))
	case "list":
		if strings.HasPrefix(path, "[") {

			var index int
			fmt.Sscanf(path, "[%d]", &index)
			inds := path[len(fmt.Sprintf("[%d]", index)):]
			if inds == "" {
				return node.ToList()[index], nil
			} else if inds[0] == '.' {
				return node.ToList()[index].Get(inds[1:])
			}
			return nil, fmt.Errorf("invalid path")
		} else {
			for _, v := range node.ToList() {
				name, err := v.Get("name")
				if err != nil || name.Type != "string" {
					continue
				}
				if strings.HasPrefix(path, name.Value.(string)) {
					inds := path[len(name.Value.(string)):]
					if inds == "" {
						return v, nil
					} else if inds[0] == '.' {
						return v.Get(inds[1:])
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("path not found")
}
