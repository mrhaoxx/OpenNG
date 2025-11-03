package ngcmd

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

type TopLevelConfig struct {
	Version  int `yamk:"version"`
	Services any `yaml:"Services,flow"`
}

var TopLevelConfigAssertion = ng.Assert{
	Type: "map",
	Sub: ng.AssertMap{
		"Services": {
			Desc: "service functions which will be called at startup",
			Type: "list",
			Sub: ng.AssertMap{
				"_": {
					Type: "map",
					Sub: ng.AssertMap{
						"name": {Type: "string", Default: "_"},
						"kind": {Type: "string", Required: true},
						"spec": {Type: "any"},
					},
				},
			},
		},
		"version": {
			Desc:     "config version",
			Type:     "int",
			Required: true,
			Forced:   true,
			Default:  6,
		},
		"Config": {
			Desc: "global configurations",
			Type: "map",
			Sub: ng.AssertMap{
				"Logger": {
					Type: "map",
					Sub: ng.AssertMap{
						"TimeZone": {
							Desc:         "time zone for logger",
							Type:         "string",
							Default:      "Local",
							Enum:         []any{"Local", "UTC", "Asia/Shanghai"},
							AllowNonEnum: true,
						},
						"Verbose": {
							Desc:    "verbose level",
							Type:    "bool",
							Default: false,
						},
					},
				},
			},
		},
	},
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

func Dedref(nodes *ng.ArgNode) error {
	var walk func(reqtree map[string]_dref, node *ng.ArgNode, path string)
	walk = func(reqtree map[string]_dref, node *ng.ArgNode, path string) {
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
		var n *ng.ArgNode

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

func AssertArg(node *ng.ArgNode, assertions ng.Assert) error {
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
		if assertions.Type != "any" && !IfCompatibleAndConvert(node, assertions) {
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
			node.Value = map[string]*ng.ArgNode{}
		}

		if subnodes, ok := node.Value.(map[string]*ng.ArgNode); ok {
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
							node := &ng.ArgNode{
								Type:  v.Type,
								Value: v.Default,
							}
							AssertArg(node, v)
							subnodes[k] = node
						} else {
							continue
						}
					}
					continue
				}
				if err := AssertArg(subnode, v); err != nil {
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
					if err := AssertArg(subnode, defaultassertion); err != nil {
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
			node.Value = []*ng.ArgNode{}
			return nil
		}

		realnodes, ok := node.Value.([]*ng.ArgNode)
		if !ok {
			return fmt.Errorf("expected list, got %T", node.Value)
		}
		for i, subnode := range realnodes {
			if err := AssertArg(subnode, defaultassertion); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}
	case "url":
		if node.Value == nil {
			node.Value = []*ngnet.URL{}
			return nil
		}
		realnode, ok := node.Value.(*ngnet.URL)
		if !ok {
			return fmt.Errorf("expected url, got %T", node.Value)
		}

		if assertions.Default != nil {
			assertnode := assertions.Default.(*ngnet.URL)

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

func IfCompatibleAndConvert(node *ng.ArgNode, assertions ng.Assert) bool {

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
			if m, ok := node.Value.(map[string]*ng.ArgNode); ok {
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
			node.Value = &ngnet.URL{
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

func validateInterfaces(a ng.Assert, v any) error {
	if v == nil {
		if a.AllowNil {
			return nil
		}
		return fmt.Errorf("nil does not implement required interfaces")
	}

	rt := reflect.TypeOf(v)

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if rv.IsNil() && !a.AllowNil {
			return fmt.Errorf("value is typed-nil for %v", rt)
		}
	}

	for _, it := range a.Impls {
		if it.Kind() != reflect.Interface {
			return fmt.Errorf("GoImplements must be interface types, got %v", it)
		}
		if !rt.Implements(it) {
			return fmt.Errorf("type %v does not implement %v", rt, it)
		}
	}
	return nil
}

func ToSchema(m ng.Assert, depth, maxDepth int) any {
	switch m.Type {
	case "int":
		res := map[string]any{
			"type":        "integer",
			"description": m.Desc,
		}
		if m.Default != nil {
			res["default"] = m.Default
		}

		if len(m.Enum) > 0 {
			if m.AllowNonEnum {
				res["anyOf"] = []any{
					map[string]any{
						"type": "integer",
					},
					map[string]any{
						"enum": m.Enum,
					},
				}
			} else {
				res["enum"] = m.Enum
			}
		}

		return res
	case "ptr":
		argsRegistry := ng.AssertionsRegistry()
		retRegistry := ng.ReturnAssertionsRegistry()

		allowedKinds := make([]string, 0, len(argsRegistry))
		for name := range argsRegistry {
			if name == "_" {
				continue
			}
			if len(m.Impls) > 0 {
				ret, ok := retRegistry[name]
				if !ok {
					continue
				}
				match := true
				for _, required := range m.Impls {
					found := false
					for _, implemented := range ret.Impls {
						if implemented == required {
							found = true
							break
						}
					}
					if !found {
						match = false
						break
					}
				}
				if !match {
					continue
				}
			}
			allowedKinds = append(allowedKinds, name)
		}

		sort.Strings(allowedKinds)

		description := "(ptr) " + m.Desc
		if len(m.Impls) > 0 {
			required := make([]string, 0, len(m.Impls))
			for _, iface := range m.Impls {
				required = append(required, iface.String())
			}
			description = fmt.Sprintf("(ptr) %s (requires: %s)", m.Desc, strings.Join(required, ", "))
		}

		stringSchema := map[string]any{
			"type":         "string",
			"description":  description,
			"errorMessage": "Pointer must reference a defined service name or be expanded inline",
		}
		if m.Default != nil {
			stringSchema["default"] = m.Default
		}

		schemas := []any{stringSchema}

		if depth < maxDepth {
			allowAnon := len(m.Impls) == 0 || len(allowedKinds) > 0
			if allowAnon {
				kindProp := map[string]any{"type": "string"}
				if len(m.Impls) > 0 && len(allowedKinds) > 0 {
					kindProp["enum"] = allowedKinds
				}

				anon := map[string]any{
					"type":        "object",
					"description": "(anonymous) " + m.Desc,
					"properties": map[string]any{
						"kind": kindProp,
						"spec": map[string]any{},
					},
					"additionalProperties": false,
				}

				conds := []any{}
				for _, name := range allowedKinds {
					value, ok := argsRegistry[name]
					if !ok {
						continue
					}
					conds = append(conds, map[string]any{
						"if": map[string]any{
							"properties": map[string]any{
								"kind": map[string]any{"const": name},
							},
							"required": []string{"kind"},
						},
						"then": map[string]any{
							"properties": map[string]any{
								"spec": ToSchema(value, depth+1, maxDepth),
							},
							"description": value.Desc,
						},
					})
				}

				if len(conds) > 0 {
					anon["allOf"] = conds
				}

				schemas = append(schemas, anon)
			}
		}

		if m.AllowNil {
			schemas = append(schemas, map[string]any{"type": "null"})
		}

		if len(schemas) == 1 {
			return schemas[0]
		}

		return map[string]any{
			"description": m.Desc,
			"anyOf":       schemas,
		}

	case "string":
		res := map[string]any{
			"type":        "string",
			"description": m.Desc,
		}
		if m.Default != nil {
			res["default"] = m.Default
		}

		if len(m.Enum) > 0 {
			if m.AllowNonEnum {
				res["anyOf"] = []any{
					map[string]any{
						"type": "string",
					},
					map[string]any{
						"enum": m.Enum,
					},
				}
			} else {
				res["enum"] = m.Enum
			}
		}

		return res
	case "bool":
		res := map[string]any{
			"type":        "boolean",
			"description": m.Desc,
		}

		if m.Default != nil {
			res["default"] = m.Default
		}

		return res

	case "map":
		if depth >= maxDepth {
			return map[string]any{
				"type":         "object",
				"description":  "(map) " + m.Desc,
				"errorMessage": "Map must be an object (max nesting depth reached)",
			}
		}
		result := map[string]any{
			"type":        "object",
			"description": m.Desc,
		}

		if sub, ok := m.Sub["_"]; !ok {
			result["additionalProperties"] = false
		} else {
			result["additionalProperties"] = ToSchema(sub, depth, maxDepth)
		}

		props := map[string]any{}

		requried := []string{}

		for key, value := range m.Sub {
			if key == "_" {
				continue
			}
			props[key] = ToSchema(value, depth+1, maxDepth)
			if value.Required {
				requried = append(requried, key)
			}
		}

		if len(props) > 0 {
			result["properties"] = props
		}

		if len(requried) > 0 {
			result["required"] = requried
		}

		return result

	case "list":
		result := map[string]any{
			"type":        "array",
			"description": m.Desc,
		}
		if def, ok := m.Sub["_"]; ok {
			result["items"] = ToSchema(def, depth+1, maxDepth)
		}

		if m.Default != nil {
			result["default"] = m.Default
		}

		return result

	case "duration":
		res := map[string]any{
			"type":         "string",
			"description":  m.Desc,
			"pattern":      "^-?(?:\\d+(?:\\.\\d+)?(?:ns|us|µs|ms|s|m|h))+$",
			"errorMessage": "Duration must be in format like '300ms', '-1.5h', '2h45m'. Valid units: ns, us (or µs), ms, s, m, h",
		}
		if m.Default != nil {
			res["default"] = m.Default
		}
		return res

	case "url":
		return map[string]any{
			"type":         "string",
			"description":  m.Desc,
			"pattern":      "^(?:(?:(?:[A-Za-z][A-Za-z0-9._-]*%)?(?:[A-Za-z][A-Za-z0-9+.-]*)://))?(?:\\[(?:[A-Fa-f0-9:.]+)\\]|(?:[A-Za-z0-9-]+\\.)*[A-Za-z0-9-]+|\\d{1,3}(?:\\.\\d{1,3}){3})?(?::\\d{1,5})?(?:/[^\\s?#]*)?(?:\\?[^\\s#]*)?(?:#[^\\s]*)?$",
			"errorMessage": "URL must be in format like 'iface%scheme://host:port/path?query#fragment'",
		}
	case "hostname":
		return map[string]any{
			"type":         "string",
			"description":  m.Desc,
			"pattern":      "^(?:\\$dref.*|[A-Za-z0-9.*-]+(?::\\d{1,5})?)$",
			"errorMessage": "Hostname must be in format like 'example.com', 'a.example.com', '*.example.com', '*'",
		}
	}

	return map[string]any{}

}
