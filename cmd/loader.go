package netgatecmd

import (
	"fmt"
	"strings"

	netgate "github.com/mrhaoxx/OpenNG"
)

type TopLevelConfig struct {
	Version  int `yamk:"version"`
	Services any `yaml:"Services,flow"`
}

var TopLevelConfigAssertion = netgate.Assert{
	Type: "map",
	Sub: netgate.AssertMap{
		"Services": {
			Desc: "service functions which will be called at startup",
			Type: "list",
			Sub: netgate.AssertMap{
				"_": {
					Type: "map",
					Sub: netgate.AssertMap{
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
			Sub: netgate.AssertMap{
				"Logger": {
					Type: "map",
					Sub: netgate.AssertMap{
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

func Dedref(nodes *netgate.ArgNode) error {
	var walk func(reqtree map[string]_dref, node *netgate.ArgNode, path string)
	walk = func(reqtree map[string]_dref, node *netgate.ArgNode, path string) {
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
		var n *netgate.ArgNode

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
