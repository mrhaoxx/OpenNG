package ui

import (
	"fmt"
)

type TopLevelConfig struct {
	Version  int       `yamk:"version"`
	Services []Service `yaml:"Services,flow"`
}

type Service struct {
	Name    string `yaml:"name"`
	Ref     string `yaml:"ref"`
	ArgsRaw any    `yaml:"args"`
}

type ArgNode struct {
	Type  string
	Value any
}

type AssertMap map[string]Assert

type Assert struct {
	Type     string
	Required bool
	Subnodes AssertMap
}

func (node *ArgNode) Assert(assertions Assert) error {
	if node.Type != assertions.Type {
		return fmt.Errorf("type mismatch: %s != %s", node.Type, assertions.Type)
	}

	switch assertions.Type {
	case "map":
		if subnodes, ok := node.Value.(map[string]ArgNode); ok {
			keys := map[string]struct{}{}
			for k := range subnodes {
				keys[k] = struct{}{}
			}

			for k, v := range assertions.Subnodes {
				subnode, ok := subnodes[k]
				if !ok {
					if v.Required {
						return fmt.Errorf("missing required key: %s", k)
					}
					continue
				}
				if err := subnode.Assert(v); err != nil {
					return fmt.Errorf("key %s: %w", k, err)
				}

				delete(keys, k)
			}

			if len(keys) > 0 {
				defaultassertion, ok := assertions.Subnodes["_"]
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
		defaultassertion, ok := assertions.Subnodes["_"]
		if !ok {
			return fmt.Errorf("missing default assertion")
		}
		realnodes, ok := node.Value.([]ArgNode)
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

func ParseFromAny(raw any) (ArgNode, error) {
	switch raw := raw.(type) {
	case string:
		return ArgNode{
			Type:  "string",
			Value: raw,
		}, nil
	case int:
		return ArgNode{
			Type:  "int",
			Value: raw,
		}, nil
	case float64:
		return ArgNode{
			Type:  "float",
			Value: raw,
		}, nil
	case bool:
		return ArgNode{
			Type:  "bool",
			Value: raw,
		}, nil
	case map[string]any:
		subnodes := make(map[string]ArgNode)
		for k, v := range raw {
			subnode, err := ParseFromAny(v)
			if err != nil {
				return ArgNode{}, err
			}
			subnodes[k] = subnode
		}
		return ArgNode{
			Type:  "map",
			Value: subnodes,
		}, nil
	case []interface{}:
		subnodes := make([]ArgNode, len(raw))
		for i, v := range raw {
			subnode, err := ParseFromAny(v)
			if err != nil {
				return ArgNode{}, err
			}
			subnodes[i] = subnode
		}
		return ArgNode{
			Type:  "list",
			Value: subnodes,
		}, nil
	default:
		return ArgNode{}, fmt.Errorf("unsupported type: %T", raw)
	}
}
