package ui

import (
	"fmt"
	"log"
	"strings"
)

type TopLevelConfig struct {
	Version  int `yamk:"version"`
	Services any `yaml:"Services,flow"`
}

type ArgNode struct {
	Type  string
	Value any
}

type AssertMap map[string]Assert

type Assert struct {
	Type     string
	Required bool
	Sub      AssertMap

	Default any
}

func (node *ArgNode) Assert(assertions Assert) error {
	if node.Type == "null" {
		if !assertions.Required {
			node.Type = assertions.Type
			node.Value = assertions.Default
		} else {
			return fmt.Errorf("required field is null")
		}
	} else {
		if assertions.Type != "any" && node.Type != assertions.Type {
			return fmt.Errorf("type mismatch: %s != %s", node.Type, assertions.Type)
		}
	}

	switch assertions.Type {
	case "map":
		if subnodes, ok := node.Value.(map[string]*ArgNode); ok {
			keys := map[string]struct{}{}
			for k := range subnodes {
				keys[k] = struct{}{}
			}

			for k, v := range assertions.Sub {
				subnode, ok := subnodes[k]
				if !ok {
					if v.Required {
						return fmt.Errorf("missing required key: %s", k)
					} else {
						if v.Default != nil {
							subnodes[k] = &ArgNode{
								Type:  v.Type,
								Value: v.Default,
							}
						} else {
							continue
						}
					}
					continue
				}
				if err := subnode.Assert(v); err != nil {
					return fmt.Errorf("key %s: %w", k, err)
				}

				delete(keys, k)
			}

			if len(keys) > 0 {
				defaultassertion, ok := assertions.Sub["_"]
				if !ok {
					return fmt.Errorf("no default assertion provided. got unexpected keys: %v", keys)
				}
				for k := range keys {
					subnode := subnodes[k]
					if err := subnode.Assert(defaultassertion); err != nil {
						return fmt.Errorf("key %s: %w", k, err)
					}
				}
			}
			return nil
		}
	case "list":
		defaultassertion, ok := assertions.Sub["_"]
		if !ok {
			return fmt.Errorf("missing default assertion")
		}
		realnodes, ok := node.Value.([]*ArgNode)
		if !ok {
			return fmt.Errorf("expected list, got %T", node.Value)
		}
		for i, subnode := range realnodes {
			if err := subnode.Assert(defaultassertion); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}
	}

	return nil
}

func ParseFromAny(raw any) (*ArgNode, error) {
	switch raw := raw.(type) {
	case nil:
		return &ArgNode{
			Type:  "null",
			Value: nil,
		}, nil
	case string:
		return &ArgNode{
			Type:  "string",
			Value: raw,
		}, nil
	case int:
		return &ArgNode{
			Type:  "int",
			Value: raw,
		}, nil
	case float64:
		return &ArgNode{
			Type:  "float",
			Value: raw,
		}, nil
	case bool:
		return &ArgNode{
			Type:  "bool",
			Value: raw,
		}, nil
	case map[string]any:
		subnodes := make(map[string]*ArgNode)
		for k, v := range raw {
			subnode, err := ParseFromAny(v)
			if err != nil {
				return nil, err
			}
			subnodes[k] = subnode
		}
		return &ArgNode{
			Type:  "map",
			Value: subnodes,
		}, nil
	case []interface{}:
		subnodes := make([]*ArgNode, len(raw))
		for i, v := range raw {
			subnode, err := ParseFromAny(v)
			if err != nil {
				return nil, err
			}
			subnodes[i] = subnode
		}
		return &ArgNode{
			Type:  "list",
			Value: subnodes,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", raw)
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

		v, ok := node.Value.(map[string]*ArgNode)[rh]
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
				return node.Value.([]*ArgNode)[index], nil
			} else if inds[0] == '.' {
				return node.Value.([]*ArgNode)[index].Get(inds[1:])
			}
			return nil, fmt.Errorf("invalid path")
		} else {
			for _, v := range node.Value.([]*ArgNode) {
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

func upperlevel(s string) string {
	if strings.HasSuffix(s, "]") {
		return s[:strings.LastIndex(s, "[")]
	}
	if strings.Contains(s, ".") {
		return s[:strings.LastIndex(s, ".")]
	}
	return ""
}

type _dref struct {
	path string
	exp  bool
}

func Dedref(nodes *ArgNode) {
	reqtree := map[string]_dref{}

	var walk func(node *ArgNode, path string)
	walk = func(node *ArgNode, path string) {
		switch node.Type {
		case "map":
			for k, v := range node.Value.(map[string]*ArgNode) {
				walk(v, path+"."+k)
			}
		case "list":
			for i, v := range node.Value.([]*ArgNode) {
				walk(v, path+"["+fmt.Sprint(i)+"]")
			}
		case "string":
			if strings.HasPrefix(node.Value.(string), "$dref{") {
				exp := strings.HasSuffix(node.Value.(string), "...")
				var dec int
				if exp {
					dec = 4
				} else {
					dec = 1
				}
				reqtree[path] = _dref{path: node.Value.(string)[6 : len(node.Value.(string))-dec], exp: exp}
			}
		default:
		}
	}

	walk(nodes, "") // find all dref nodes

	t, err := nodes.Get("[0]")
	log.Println(t, err)

	for k, v := range reqtree {
		var err error
		_k := k
		__v := ""

	next:
		k = upperlevel(k)
		var n *ArgNode

		if k != "" {
			__v = k + "." + v.path
		} else {
			__v = v.path
		}

		n, err = nodes.Get(__v)

		if err != nil {
			if k == "" {
				continue
			}
			goto next
		} else {

			fmt.Println(__v, "->", _k)

			__k := upperlevel(_k)

			if __k == "" {
				continue
			}

			parent, _ := nodes.Get(__k)

			thislevel := _k[len(__k):]

			switch parent.Type {
			case "map":
				parent.Value.(map[string]*ArgNode)[thislevel[1:]] = n
			case "list":
				var index int
				fmt.Sscanf(thislevel, "[%d]", &index)

				if v.exp {
					if n.Type != "list" {
						continue
					}
					parent.Value = append(parent.Value.([]*ArgNode)[:index], append(n.Value.([]*ArgNode), parent.Value.([]*ArgNode)[index+1:]...)...)
				} else {
					parent.Value.([]*ArgNode)[index] = n
				}
			default:
				continue
			}

			delete(reqtree, _k)
		}
	}

	if len(reqtree) > 0 {
		log.Println("unresolved dref nodes", reqtree)
	}

}
