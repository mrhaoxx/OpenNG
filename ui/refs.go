package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/net"
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
			ref, ok = _builtin_refs[_ref]
			if !ok {
				return fmt.Errorf("kind not found: %s", fmt.Sprintf("[%d] ", i)+_ref)
			}
		}

		spec := _srv.MustGet("spec")

		spec_assert, ok := _builtin_refs_assertions[_ref]
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

			log.Errorf("%s", ret_err)

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

			log.Errorf("%s", ret_err)

			if !reload {
				return ret_err
			} else {
				reload_errors = append(reload_errors, ret_err)
				continue
			}
		}

		space.Services[to] = inst

		used_time := fmt.Sprintf("[%4d][%10s]", i, time.Since(_time).String())

		if to != "_" {
			log.Println(used_time, _ref, "->", to)
		} else {
			log.Println(used_time, _ref)
		}

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
			v, ok := space.Services[node.Value.(string)]
			if ok {
				node.Value = v
			} else {
				return fmt.Errorf("ptr not found: %s", node.Value.(string))
			}
		}
		return nil
	}

	return walk(root)
}

func LoadCfg(cfgs []byte, reload bool) error {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}

	curcfg = cfgs

	nodes, err := ParseFromAny(cfg)
	if err != nil {
		return err
	}

	err = Dedref(nodes)

	if err != nil {
		return err
	}

	err = nodes.Assert(_builtin_refs_assertions["_"])

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
		Refs:     _builtin_refs,
		Services: map[string]any{},
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
				log.TZ = _tz
			}

			fmt.Fprintln(os.Stderr, "timezone:", tz)
		}

		if verb := logger.MustGet("Verbose").ToBool(); verb {
			log.Verb = true
			fmt.Fprintln(os.Stderr, "verbose log mode enabled")
		}

		if !logger.MustGet("EnableConsoleLogger").ToBool() {
			log.Loggers.Loggers = []log.Logger{}
			fmt.Fprintln(os.Stderr, "console log disabled")
		}

		if logger.MustGet("EnableSSELogger").ToBool() {
			log.Loggers.Loggers = append(log.Loggers.Loggers, Sselogger)
			fmt.Fprintln(os.Stderr, "SSE logger enabled")

		}

		if file, err := logger.Get("FileLogger"); err == nil {
			f, _ := os.OpenFile(file.MustGet("Path").ToString(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			log.Loggers.Loggers = append(log.Loggers.Loggers, f)
			fmt.Fprintln(os.Stderr, "file logger enabled:", file.MustGet("Path").ToString())
		}

		if udp, err := logger.Get("UDPLogger"); err == nil {
			log.Loggers.Loggers = append(log.Loggers.Loggers, NewUdpLogger(udp.MustGet("Addr").ToString()))
			fmt.Fprintln(os.Stderr, "UDP logger enabled:", udp.MustGet("Addr").ToString())
		}
	}
	return nil
}
