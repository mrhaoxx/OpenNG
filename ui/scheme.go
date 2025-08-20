package ui

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
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
			"type":         "string",
			"description":  "(ptr) " + m.Desc,
			"errorMessage": "Pointer must be a string",
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

func ValidateConfig(root *ArgNode) []error {

	errors := []error{}

	srvs := root.MustGet("Services")

	space := Space{
		Services: map[string]any{},
	}

	for i, _srv := range srvs.Value.([]*ArgNode) {

		_ref := _srv.MustGet("kind").ToString()
		to := _srv.MustGet("name").ToString()

		spec := _srv.MustGet("spec")

		spec_assert, ok := _builtin_refs_assertions[_ref]
		if !ok {
			errors = append(errors, fmt.Errorf("%s assert not found: %s", fmt.Sprintf("[%d]", i), _ref))
			continue
		}

		err := spec.Assert(spec_assert)

		if err != nil {
			errors = append(errors, fmt.Errorf("%s assert failed: %s %w", fmt.Sprintf("[%d]", i), _ref, err))
			continue
		}

		err = space.Deptr(spec)

		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err))
			continue
		}

		if to != "" && to != "_" {
			space.Services[to] = true
		}

	}

	return errors
}

func ValidateCfg(cfgs []byte) []string {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return []string{err.Error()}
	}

	curcfg = cfgs

	nodes, err := ParseFromAny(cfg)
	if err != nil {
		return []string{err.Error()}
	}

	err = Dedref(nodes)

	if err != nil {
		return []string{err.Error()}
	}

	err = nodes.Assert(_builtin_refs_assertions["_"])

	if err != nil {
		return []string{err.Error()}
	}

	errors := ValidateConfig(nodes)

	errs := []string{}

	if len(errors) > 0 {
		for _, err := range errors {
			errs = append(errs, err.Error())
		}
		return errs
	}

	return nil
}
