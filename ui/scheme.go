package ui

import (
	"encoding/json"
)

func (m Assert) ToScheme() any {
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
		return map[string]any{
			"type":        "string",
			"description": "(ptr) " + m.Desc,
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
		result := map[string]any{
			"type":        "object",
			"description": m.Desc,
		}

		if sub, ok := m.Sub["_"]; !ok {
			result["additionalProperties"] = false
		} else {
			result["additionalProperties"] = sub.ToScheme()
		}

		props := map[string]any{}

		requried := []string{}

		for key, value := range m.Sub {
			if key == "_" {
				continue
			}
			props[key] = value.ToScheme()
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
			result["items"] = def.ToScheme()
		}

		if m.Default != nil {
			result["default"] = m.Default
		}

		return result
	}

	return map[string]any{}
}

func GenerateJsonSchema() []byte {

	root := _builtin_refs_assertions["_"].ToScheme().(map[string]any)

	root["$scheme"] = "https://json-schema.org/draft/2020-12/schema"

	services := root["properties"].(map[string]any)["Services"].(map[string]any)["items"].(map[string]any)

	allOf := []any{}

	for k, v := range _builtin_refs_assertions {

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
					"spec": v.ToScheme(),
				},
			},
		})
	}

	if len(allOf) > 0 {
		services["allOf"] = allOf
	}

	s, _ := json.Marshal(root)

	return s
}
