package ui

import (
	"fmt"
	"log"
)

type Inst func(*ArgNode) (any, error)

type Space struct {
	Refs map[string]Inst

	Services map[string]any
}

func (space *Space) Apply(root *ArgNode) error {

	srvs := root.MustGet("Services")

	for _, _srv := range srvs.Value.([]*ArgNode) {
		_ref := _srv.MustGet("kind").ToString()
		ref, ok := space.Refs[_ref]
		if !ok {
			ref, ok = _builtin_refs[_ref]
			if !ok {
				return fmt.Errorf("kind not found: %s", _ref)
			}
		}

		spec := _srv.MustGet("spec")

		spec_assert, ok := _builtin_refs_assertions[_ref]
		if !ok {
			return fmt.Errorf("assert not found: %s", _ref)
		}

		err := spec.Assert(spec_assert)

		if err != nil {
			return err
		}

		err = space.Deptr(spec)

		if err != nil {
			return err
		}

		inst, err := ref(spec)

		log.Println(err, inst, "<-", ref, _ref, spec)

		if err != nil {
			return err
		}

		to := _srv.MustGet("name").Value.(string)
		if to != "_" {
			space.Services[to] = inst
		}
	}
	return nil

}

func (space *Space) Deptr(root *ArgNode) error {
	if root == nil {
		return nil
	}

	var walk func(*ArgNode) error
	walk = func(node *ArgNode) error {
		switch node.Type {
		case "map":
			for k, v := range node.ToMap() {
				err := walk(v)
				if err != nil {
					return fmt.Errorf(".%s%w", k, err)
				}
			}
		case "list":
			for i, v := range node.ToList() {
				err := walk(v)
				if err != nil {
					return fmt.Errorf("[%d]%w", i, err)
				}
			}
		case "ptr":
			v, ok := space.Services[node.Value.(string)]
			if ok {
				node.Value = v
			} else {
				return fmt.Errorf(" ptr not found: %s", node.Value.(string))
			}
		}
		return nil
	}

	return walk(root)
}
