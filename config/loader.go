package config

import (
	"fmt"
	"os"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/net"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type Inst func(*ArgNode) (any, error)

type Space struct {
	Refs map[string]Inst

	Services map[string]any
}

func (space *Space) Apply(root *ArgNode, reload bool) error {

	reload_errors := []error{}

	srvs := root.MustGet("Services")

	for i, _srv := range srvs.Value.([]*ArgNode) {
		_time := time.Now()

		_ref := _srv.MustGet("kind").ToString()
		to := _srv.MustGet("name").ToString()

		ref, ok := space.Refs[_ref]
		if !ok {
			ref, ok = refs[_ref]
			if !ok {
				return fmt.Errorf("kind not found: %s", fmt.Sprintf("[%d] ", i)+_ref)
			}
		}

		spec := _srv.MustGet("spec")

		spec_assert, ok := refs_assertions[_ref]
		if !ok {
			return fmt.Errorf("assert not found: %s", fmt.Sprintf("[%d] ", i)+_ref)
		}

		err := spec.Assert(spec_assert)

		if err != nil {
			return fmt.Errorf("%s: assert failed: %w", fmt.Sprintf("[%d] ", i)+_ref, err)
		}

		err = space.Deptr(spec, false)

		if err != nil {
			ret_err := fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)

			zlog.Error().Caller().Str("err", ret_err.Error()).Msg("failed to deptr")

			if !reload {
				return ret_err
			} else {
				reload_errors = append(reload_errors, ret_err)
				continue
			}
		}

		inst, err := ref(spec)

		if err != nil {
			ret_err := fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)

			zlog.Error().Caller().Str("err", ret_err.Error()).Msg("failed to call ref")

			if !reload {
				return ret_err
			} else {
				reload_errors = append(reload_errors, ret_err)
				continue
			}
		}

		space.Services[to] = inst

		// used_time := fmt.Sprintf("[%4d][%10s]", i, time.Since(_time).String())

		zlog.Info().Str("kind", _ref).Str("name", to).Dur("elapsed", time.Since(_time)).Int("index", i).Msg("service applied")

	}

	if reload && len(reload_errors) > 0 {
		var errstr string
		for _, e := range reload_errors {
			errstr += e.Error() + "\n"
		}
		return fmt.Errorf("Reload Failed:\n%s", errstr)
	}

	return nil

}

func (space *Space) Deptr(root *ArgNode, validate bool) error {
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
					return fmt.Errorf(".%s: %w", k, err)
				}
			}
		case "list":
			for i, v := range node.ToList() {
				err := walk(v)
				if err != nil {
					return fmt.Errorf("[%d]: %w", i, err)
				}
			}
		case "url":
			if node.Value == nil {
				node.Value = []*net.URL{}
				return nil
			}
			realnode, ok := node.Value.(*net.URL)
			if !ok {
				return fmt.Errorf("expected url, got %T", node.Value)
			}
			if realnode.Interface != "" {
				v, ok := space.Services[realnode.Interface]
				if ok {
					if !validate {
						node.Value.(*net.URL).Underlying = v.(net.Interface)
					}
				} else {
					return fmt.Errorf("url interface not found: %s", realnode.Interface)
				}
			}
		case "ptr":
			switch v := node.Value.(type) {
			case string:
				if svc, ok := space.Services[v]; ok {
					node.Value = svc
				} else {
					return fmt.Errorf("ptr not found: %s", v)
				}
			case map[string]*ArgNode:
				inst, err := space.instantiateAnon(v, validate)
				if err != nil {
					return err
				}
				node.Value = inst
			case *ArgNode:
				if v.Type != "map" {
					return fmt.Errorf("invalid anonymous ptr node type: %s", v.Type)
				}
				mm := v.Value.(map[string]*ArgNode)
				inst, err := space.instantiateAnon(mm, validate)
				if err != nil {
					return err
				}
				node.Value = inst
			default:
				return fmt.Errorf("ptr expects name or inline anonymous object, got %T", node.Value)
			}
		}
		return nil
	}

	return walk(root)
}

func (space *Space) instantiateAnon(m map[string]*ArgNode, validate bool) (any, error) {
	var kind string
	if k, ok := m["kind"]; ok && k != nil {
		if k.Type != "string" {
			return nil, fmt.Errorf("anonymous object: kind must be string")
		}
		kind = k.ToString()
	} else {
		return nil, fmt.Errorf("anonymous object missing kind")
	}

	spec := &ArgNode{Type: "null", Value: nil}
	if s, ok := m["spec"]; ok && s != nil {
		spec = s
	}

	specAssert, ok := refs_assertions[kind]
	if !ok {
		return nil, fmt.Errorf("assert not found: %s", kind)
	}
	if err := spec.Assert(specAssert); err != nil {
		return nil, fmt.Errorf("%s: assert failed: %w", kind, err)
	}

	if err := space.Deptr(spec, validate); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}

	ref, ok := space.Refs[kind]
	if !ok {
		ref, ok = refs[kind]
		if !ok {
			return nil, fmt.Errorf("kind not found: %s", kind)
		}
	}

	if validate {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
	}

	inst, err := ref(spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	return inst, nil
}

func LoadCfg(cfgs []byte, reload bool) error {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}

	nodes, err := ParseFromAny(cfg)
	if err != nil {
		return err
	}

	err = Dedref(nodes)

	if err != nil {
		return err
	}

	err = nodes.Assert(refs_assertions["_"])

	if err != nil {
		return err
	}

	if !reload {
		err = GlobalCfg(nodes.MustGet("Config"))

		if err != nil {
			return err
		}
	}

	space := Space{
		Refs: refs,
		Services: map[string]any{
			"sys": &net.SysInterface{},
		},
	}

	space.Services["@"] = space

	err = space.Apply(nodes, reload)

	return err
}

func GlobalCfg(config *ArgNode) error {

	if logger, err := config.Get("Logger"); err == nil {

		if tz := logger.MustGet("TimeZone").ToString(); tz != "Local" {
			_tz, err := time.LoadLocation(tz)
			if err != nil {
				return err
			} else {
				zerolog.TimestampFunc = func() time.Time {
					return time.Now().In(_tz)
				}
			}

			fmt.Fprintln(os.Stderr, "timezone:", tz)
		}

		if verb := logger.MustGet("Verbose").ToBool(); verb {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			fmt.Fprintln(os.Stderr, "verbose log mode enabled")
		}

		if !logger.MustGet("EnableConsoleLogger").ToBool() {
			log.Loggers.Loggers = []log.Logger{}
			fmt.Fprintln(os.Stderr, "console log disabled")
		}
	}
	return nil
}

func ValidateCfg(cfgs []byte) []string {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return []string{err.Error()}
	}
	nodes, err := ParseFromAny(cfg)
	if err != nil {
		return []string{err.Error()}
	}

	err = Dedref(nodes)

	if err != nil {
		return []string{err.Error()}
	}

	err = nodes.Assert(refs_assertions["_"])

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
