package ngcmd

import (
	"fmt"
	"strings"

	ng "github.com/mrhaoxx/OpenNG"
)

type TopLevelConfig struct {
	Version  int `yamk:"version"`
	Services any `yaml:"Services,flow"`
}

var TopLevelConfigAssertion = ng.Assert{
	Type: "map",
	Sub: ng.AssertMap{
		"Services": {
			Desc: "service definitions (map-by-name or legacy list)",
			Type: "any",
		},
		"version": {
			Desc:     "config version",
			Type:     "int",
			Required: true,
			// Forced:   true,
			Default: 6,
		},
		"Config": {
			Desc: "global configurations",
			Type: "map",
			Sub: ng.AssertMap{
				"Logger": {
					Type: "map",
					Sub: ng.AssertMap{
						"TimeZone": {
							Desc:    "time zone for logger",
							Type:    "string",
							Default: "Local",
							// Enum:         []any{"Local", "UTC", "Asia/Shanghai"},
							// AllowNonEnum: true,
						},
						"Outputs": {
							Desc:    "log outputs: stdout, stderr, or file path",
							Type:    "list",
							Default: []*ng.ArgNode{{Type: "string", Value: "stdout"}},
							Sub:     ng.AssertMap{"_": {Type: "string"}},
						},
						"Verbose": {
							Desc: "verbose level",
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
	var walk func(reqtree map[string]_dref, node *ng.ArgNode, path string, depth int)
	walk = func(reqtree map[string]_dref, node *ng.ArgNode, path string, depth int) {
		if depth > 50 {
			return
		}
		switch node.Type {
		case "map":
			for k, v := range node.ToMap() {
				if path != "" {
					walk(reqtree, v, path+"."+k, depth+1)
				} else {
					walk(reqtree, v, k, depth+1)
				}
			}
		case "list":
			for i, v := range node.ToList() {
				walk(reqtree, v, path+"["+fmt.Sprint(i)+"]", depth+1)
			}
		case "dref":
			reqtree[path] = _dref{path: node.Value.(string), exp: false}
		case "dref...":
			reqtree[path] = _dref{path: node.Value.(string), exp: true}

		default:
		}
	}

	regenCount := 0

_regen:
	if regenCount > 100 {
		return fmt.Errorf("dref resolution exceeded max iterations (possible circular reference)")
	}
	regenCount++

	reqtree := map[string]_dref{}

	walk(reqtree, nodes, "", 0) // find all dref nodes

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

			// Detect direct self-reference (n == parent would create a cycle)
			if n == parent {
				delete(reqtree, _k)
				continue
			}

			switch parent.Type {
			case "map":
				parent.ToMap()[thislevel[1:]] = n.DeepCopy()
			case "list":
				var index int
				fmt.Sscanf(thislevel, "[%d]", &index)

				if v.exp {
					if n.Type != "list" {
						return fmt.Errorf("expected list got %s", n.Type)
					}

					regen = true // here makes copies, so we need regen the dref table
					// Deep copy each expanded item
					copied := make([]*ng.ArgNode, len(n.ToList()))
					for ci, item := range n.ToList() {
						copied[ci] = item.DeepCopy()
					}
					if index == len(parent.ToList()) {
						parent.Value = append(parent.ToList(), copied...)
					} else {
						parent.Value = append(parent.ToList()[:index], append(copied, parent.ToList()[index+1:]...)...)
					}
				} else {
					parent.ToList()[index] = n.DeepCopy()
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
