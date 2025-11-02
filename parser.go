package netgate

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/net"
)

type ArgNode struct {
	Type  string
	Value any
}

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

func (node *ArgNode) Assert(assertions Assert) error {
	if node == nil {
		if assertions.Type == "null" || assertions.Type == "any" {
			return nil
		} else {
			return fmt.Errorf("required field is nil")
		}
	}
	if node.Type == "null" {
		if !assertions.Required {
			node.Type = assertions.Type
			node.Value = assertions.Default
		} else {
			return fmt.Errorf("required field is null")
		}
	} else {
		if assertions.Type != "any" && !node.IfCompatibleAndConvert(assertions) {
			return fmt.Errorf("type incompatible: %s !-> %s (%v)", node.Type, assertions.Type, node.Value)
		}
		if assertions.Forced && assertions.Default != nil && assertions.Type != "url" {
			if !reflect.DeepEqual(node.Value, assertions.Default) {
				return fmt.Errorf("forced field not met requirements wanted: %v, got: %v", assertions.Default, node.Value)
			}
		}
	}

	switch assertions.Type {
	case "map":
		if node.Value == nil {
			node.Value = map[string]*ArgNode{}
		}

		if subnodes, ok := node.Value.(map[string]*ArgNode); ok {
			keys := map[string]struct{}{}
			for k := range subnodes {
				keys[k] = struct{}{}
			}

			for k, v := range assertions.Sub {
				subnode, ok := subnodes[k]
				if !ok {
					if v.Required {
						return fmt.Errorf("missing required key: %s", strconv.Quote(k))
					} else {
						if v.Default != nil {
							node := &ArgNode{
								Type:  v.Type,
								Value: v.Default,
							}
							node.Assert(v)
							subnodes[k] = node
						} else {
							continue
						}
					}
					continue
				}
				if err := subnode.Assert(v); err != nil {
					return fmt.Errorf("key %s: %w", strconv.Quote(k), err)
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
						return fmt.Errorf("key %s: %w", strconv.Quote(k), err)
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

		if node.Value == nil {
			node.Value = []*ArgNode{}
			return nil
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
	case "url":
		if node.Value == nil {
			node.Value = []*net.URL{}
			return nil
		}
		realnode, ok := node.Value.(*net.URL)
		if !ok {
			return fmt.Errorf("expected url, got %T", node.Value)
		}

		if assertions.Default != nil {
			assertnode := assertions.Default.(*net.URL)

			if assertions.Forced && realnode.Interface != assertnode.Interface {
				return fmt.Errorf("url interface mismatch: %s != %s", realnode.Interface, assertnode.Interface)
			}

			if assertnode.Interface != "" {

				if realnode.Interface == "" {
					realnode.Interface = assertnode.Interface
				}
			}
			if assertnode.URL.Scheme != "" {
				if assertions.Forced && realnode.URL.Scheme != assertnode.URL.Scheme {
					return fmt.Errorf("url scheme mismatch: %s != %s", realnode.URL.Scheme, assertnode.URL.Scheme)
				}
				if realnode.URL.Scheme == "" {
					realnode.URL.Scheme = assertnode.URL.Scheme
				}
			}
			if assertnode.URL.Host != "" {
				if assertions.Forced && realnode.URL.Host != assertnode.URL.Host {
					return fmt.Errorf("url host mismatch: %s != %s", realnode.URL.Host, assertnode.URL.Host)
				}
				if realnode.URL.Host == "" {
					realnode.URL.Host = assertnode.URL.Host
				}
			}
			if assertnode.URL.Path != "" {
				if assertions.Forced && realnode.URL.Path != assertnode.URL.Path {
					return fmt.Errorf("url path mismatch: %s != %s", realnode.URL.Path, assertnode.URL.Path)
				}
				if realnode.URL.Path == "" {
					realnode.URL.Path = assertnode.URL.Path
				}
			}
			if assertnode.URL.RawQuery != "" {
				if assertions.Forced && realnode.URL.RawQuery != assertnode.URL.RawQuery {
					return fmt.Errorf("url query mismatch: %s != %s", realnode.URL.RawQuery, assertnode.URL.RawQuery)
				}
				if realnode.URL.RawQuery == "" {
					realnode.URL.RawQuery = assertnode.URL.RawQuery
				}
			}
			if assertnode.URL.RawFragment != "" {
				if assertions.Forced && realnode.URL.RawFragment != assertnode.URL.RawFragment {
					return fmt.Errorf("url fragment mismatch: %s != %s", realnode.URL.RawFragment, assertnode.URL.RawFragment)
				}
				if realnode.URL.RawFragment == "" {
					realnode.URL.RawFragment = assertnode.URL.RawFragment
				}
			}
		}
	}

	return nil
}

func (node *ArgNode) IfCompatibleAndConvert(assertions Assert) bool {

	if node.Type == assertions.Type {
		return true
	}

	switch assertions.Type {
	case "ptr":
		if node.Type == "string" {
			node.Type = "ptr"
			return true
		}
		if node.Type == "map" {
			if m, ok := node.Value.(map[string]*ArgNode); ok {
				if _, ok := m["kind"]; ok {
					node.Type = "ptr"
					return true
				}
			}
		}
	case "duration":
		if node.Type == "string" {
			if dur, err := time.ParseDuration(node.Value.(string)); err == nil {
				node.Type = "duration"
				node.Value = dur
				return true
			}
		}
	case "url": // iface%scheme://host:port/path?query#fragment
		if node.Type == "string" {
			str := node.Value.(string)
			idx_percent := strings.Index(str, "%")
			idx_colon := strings.Index(str, ":")
			iface_ptr := ""

			if idx_percent != -1 {
				if idx_percent < idx_colon {
					iface_ptr = str[:idx_percent]
					str = str[idx_percent+1:]
				}
			}

			_url, err := url.Parse(str)
			if err != nil {
				return false
			}

			node.Type = "url"
			node.Value = &net.URL{
				Interface: iface_ptr,
				URL:       *_url,
			}
			return true
		}
	case "hostname": // should be a valid hostname, use regexp to check
		if node.Type == "string" {
			re := regexp2.MustCompile(`^[A-Za-z0-9.*-]+(?::\d{1,5})?$`, regexp2.RE2)
			if ok, _ := re.MatchString(node.Value.(string)); ok {
				node.Type = "hostname"
				return true
			}
		}
	}

	return false
}

func ParseFromAny(raw any) (*ArgNode, error) {
	switch raw := raw.(type) {
	case nil:
		return &ArgNode{
			Type:  "null",
			Value: nil,
		}, nil
	case string:
		switch {
		case strings.HasPrefix(raw, "$dref{"):
			{
				if strings.HasSuffix(raw, "...") {
					return &ArgNode{
						Type:  "dref...",
						Value: raw[len("$dref{") : len(raw)-4],
					}, nil
				}
				return &ArgNode{
					Type:  "dref",
					Value: raw[len("$dref{") : len(raw)-1],
				}, nil
			}
		default:
			return &ArgNode{
				Type:  "string",
				Value: raw,
			}, nil
		}
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

func (node *ArgNode) ToValue() any {
	if node == nil {
		return nil
	}
	switch node.Type {
	case "map":
		ret := map[string]any{}
		for k, v := range node.Value.(map[string]*ArgNode) {
			ret[k] = v.ToValue()
		}
		return ret

	case "list":
		ret := make([]any, len(node.ToList()))
		for i, v := range node.ToList() {
			ret[i] = v.ToValue()
		}
		return ret
	default:
		return node.Value
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

func Dedref(nodes *ArgNode) error {
	var walk func(reqtree map[string]_dref, node *ArgNode, path string)
	walk = func(reqtree map[string]_dref, node *ArgNode, path string) {
		switch node.Type {
		case "map":
			for k, v := range node.ToMap() {
				if path != "" {
					walk(reqtree, v, path+"."+k)
				} else {
					walk(reqtree, v, k)
				}
			}
		case "list":
			for i, v := range node.ToList() {
				walk(reqtree, v, path+"["+fmt.Sprint(i)+"]")
			}
		case "dref":
			reqtree[path] = _dref{path: node.Value.(string), exp: false}
		case "dref...":
			reqtree[path] = _dref{path: node.Value.(string), exp: true}

		default:
		}
	}

_regen:

	reqtree := map[string]_dref{}

	walk(reqtree, nodes, "") // find all dref nodes

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

			__k := upperlevel(_k)

			if __k == "" {
				continue
			}

			parent, _ := nodes.Get(__k)

			thislevel := _k[len(__k):]

			regen := false

			switch parent.Type {
			case "map":
				parent.ToMap()[thislevel[1:]] = n
			case "list":
				var index int
				fmt.Sscanf(thislevel, "[%d]", &index)

				if v.exp {
					if n.Type != "list" {
						return fmt.Errorf("expected list got %s", n.Type)
					}

					regen = true // here makes copies, so we need regen the dref table
					if index == len(parent.ToList()) {
						parent.Value = append(parent.ToList(), n.ToList()...)
					} else {
						parent.Value = append(parent.ToList()[:index], append(n.ToList(), parent.ToList()[index+1:]...)...)
					}
				} else {
					parent.ToList()[index] = n
				}
			default:
				continue
			}

			delete(reqtree, _k)

			if regen {
				goto _regen
			}
		}
	}

	if len(reqtree) > 0 {
		return fmt.Errorf("unresolved dref nodes %v", reqtree)
	}

	return nil

}
