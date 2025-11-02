package netgatecmd

import netgate "github.com/mrhaoxx/OpenNG"

func ToScheme(m netgate.Assert, depth, maxDepth int) any {
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
		if depth >= maxDepth {
			return map[string]any{
				"type":         "string",
				"description":  "(ptr) " + m.Desc,
				"errorMessage": "Pointer must be a string (max nesting depth reached)",
			}
		}

		anon := map[string]any{
			"type":        "object",
			"description": "(anonymous) " + m.Desc,
			"properties": map[string]any{
				"kind": map[string]any{"type": "string"},
				"spec": map[string]any{},
			},
			"additionalProperties": false,
		}

		conds := []any{}
		for k, v := range netgate.AssertionsRegistry() {
			if k == "_" {
				continue
			}
			conds = append(conds, map[string]any{
				"if": map[string]any{
					"properties": map[string]any{
						"kind": map[string]any{"const": k},
					},
					"required": []string{"kind"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"spec": ToScheme(v, depth+1, maxDepth),
					},
					"description": v.Desc,
				},
			})
		}
		if len(conds) > 0 {
			anon["allOf"] = conds
		}

		return map[string]any{
			"description": m.Desc,
			"anyOf": []any{
				map[string]any{
					"type":         "string",
					"description":  "(ptr) " + m.Desc,
					"errorMessage": "Pointer must be a string or an anonymous object",
				},
				anon,
			},
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
			result["additionalProperties"] = ToScheme(sub, depth, maxDepth)
		}

		props := map[string]any{}

		requried := []string{}

		for key, value := range m.Sub {
			if key == "_" {
				continue
			}
			props[key] = ToScheme(value, depth+1, maxDepth)
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
			result["items"] = ToScheme(def, depth+1, maxDepth)
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
