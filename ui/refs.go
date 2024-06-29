package ui

import "fmt"

type Inst func(ArgNode) (any, error)

type Space struct {
	Refs map[string]Inst

	Services map[string]any
}

func (space *Space) Apply(srvs ArgNode) error {
	for _, _srv := range srvs.Value.([]ArgNode) {
		srv := _srv.Value.(map[string]ArgNode)
		_ref := srv["ref"].Value.(string)
		ref, ok := space.Refs[_ref]
		if !ok {
			return fmt.Errorf("ref not found: %s", _ref)
		}

		inst, err := ref(srv["args"].Value.(ArgNode))

		if err != nil {
			return err
		}

		space.Services[srv["name"].Value.(string)] = inst
	}
	return nil

}
