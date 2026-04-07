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

	// Build per-kind if/then conditions for service entries
	allOf := []any{}
	for k, v := range refs_assertions {
		if k == "_" {
			continue
		}
		thenSchema := ToSchema(v, 0, 6)
		thenProps := map[string]any{}
		if m, ok := thenSchema.(map[string]any); ok {
			if p, ok := m["properties"].(map[string]any); ok {
				thenProps = p
			}
		}
		// Include "kind" in then.properties so additionalProperties works
		thenProps["kind"] = map[string]any{"const": k}
		thenRequired := []string{"kind"}
		if m, ok := thenSchema.(map[string]any); ok {
			if r, ok := m["required"].([]string); ok {
				thenRequired = append(thenRequired, r...)
			}
		}
		allOf = append(allOf, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"kind": map[string]any{"const": k},
				},
			},
			"then": map[string]any{
				"properties":            thenProps,
				"required":              thenRequired,
				"additionalProperties":  false,
				"description":           v.Desc,
			},
		})
	}

	// Service entry schema: {kind: string, ...fields} with if/then per kind
	serviceEntry := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"kind": map[string]any{
				"type":        "string",
				"description": "service type identifier",
			},
		},
		"required": []string{"kind"},
	}
	if len(allOf) > 0 {
		serviceEntry["allOf"] = allOf
	}

	root := ToSchema(ngcmd.TopLevelConfigAssertion, 0, 5)
	rootMap, ok := root.(map[string]any)
	if !ok {
		rootMap = map[string]any{}
	}
	rootMap["$schema"] = "https://json-schema.org/draft/2020-12/schema"

	// Override Services as map of name → service entry
	if props, ok := rootMap["properties"].(map[string]any); ok {
		props["Services"] = map[string]any{
			"type":                 "object",
			"description":         "service definitions",
			"additionalProperties": serviceEntry,
		}
	}

	s, _ := json.Marshal(rootMap)
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
					},
				}

				conds := []any{}
				for _, name := range allowedKinds {
					value, ok := argsRegistry[name]
					if !ok {
						continue
					}
					thenSchema := ToSchema(value, depth+1, maxDepth)
					thenProps := map[string]any{}
					if sm, ok := thenSchema.(map[string]any); ok {
						if p, ok := sm["properties"].(map[string]any); ok {
							thenProps = p
						}
					}
					conds = append(conds, map[string]any{
						"if": map[string]any{
							"properties": map[string]any{
								"kind": map[string]any{"const": name},
							},
							"required": []string{"kind"},
						},
						"then": map[string]any{
							"properties":  thenProps,
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
