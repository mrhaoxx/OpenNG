package ui

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	ng "github.com/mrhaoxx/OpenNG"
	ngcmd "github.com/mrhaoxx/OpenNG/cmd"
)

func GenerateJsonSchema() []byte {
	refs_assertions := ng.AssertionsRegistry()

	root := ToSchema(ngcmd.TopLevelConfigAssertion, 0, 5).(map[string]any)

	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"

	services := root["properties"].(map[string]any)["Services"].(map[string]any)["items"].(map[string]any)

	allOf := []any{}

	for k, v := range refs_assertions {

		if k == "_" {
			continue
		}

		allOf = append(allOf, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"kind": map[string]any{
						"const": k,
					},
				},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"spec": ToSchema(v, 0, 6),
				},
				"description": v.Desc,
			},
		})
	}

	if len(allOf) > 0 {
		services["allOf"] = allOf
	}

	s, _ := json.Marshal(root)

	return s
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
						if required.Kind() == reflect.Interface {
							if implemented.Implements(required) {
								found = true
								break
							}
						} else if implemented.AssignableTo(required) {
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

		// if len(m.Enum) > 0 {
		// 	if m.AllowNonEnum {
		// 		res["anyOf"] = []any{
		// 			map[string]any{
		// 				"type": "string",
		// 			},
		// 			map[string]any{
		// 				"enum": m.Enum,
		// 			},
		// 		}
		// 	} else {
		// 		res["enum"] = m.Enum
		// 	}
		// }

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
		if len(m.SubList) > 0 {
			prefix := make([]any, 0, len(m.SubList))
			for _, sub := range m.SubList {
				prefix = append(prefix, ToSchema(sub, depth+1, maxDepth))
			}
			result["prefixItems"] = prefix
		}
		if def, ok := m.Sub["_"]; ok {
			result["items"] = ToSchema(def, depth+1, maxDepth)
		} else if len(m.SubList) > 0 {
			// result["items"] = false // no default assertion means extra entries are forbidden
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

	case "regexp":
		return map[string]any{
			"type":         "string",
			"description":  m.Desc,
			"errorMessage": "Regexp must be a valid regular expression pattern",
		}
	}

	return map[string]any{}

}
