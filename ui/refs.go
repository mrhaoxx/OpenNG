package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/mrhaoxx/OpenNG/log"
	"gopkg.in/yaml.v3"
)

type Inst func(*ArgNode) (any, error)

type Space struct {
	Refs map[string]Inst

	Services map[string]any
}

func (space *Space) Apply(root *ArgNode) error {

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

		err = space.Deptr(spec)

		if err != nil {
			return fmt.Errorf("%s: deptr failed: %w", fmt.Sprintf("[%d] ", i)+_ref, err)
		}

		inst, err := ref(spec)

		if err != nil {
			return fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)
		}

		space.Services[to] = inst

		used_time := fmt.Sprintf("[%4d][%10s]", i, time.Since(_time).String())

		if to != "_" {
			log.Println(used_time, _ref, "->", to)
		} else {
			log.Println(used_time, _ref)
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
				return fmt.Errorf("ptr not found: %s", node.Value.(string))
			}
		}
		return nil
	}

	return walk(root)
}

func LoadCfg(cfgs []byte) error {
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

	err = GlobalCfg(nodes.MustGet("Config"))

	if err != nil {
		return err
	}

	space := Space{
		Refs:     _builtin_refs,
		Services: map[string]any{},
	}

	space.Services["@"] = space

	err = space.Apply(nodes)

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
			log.Println("sys", "Disabling Console Logging")
			log.Loggers = []log.Logger{}
		}

		if logger.MustGet("EnableSSELogger").ToBool() {
			log.Loggers = append(log.Loggers, Sselogger)
			log.Println("sys", "SSE Logger Registered")
		}

		if file, err := logger.Get("FileLogger"); err == nil {
			f, _ := os.OpenFile(file.MustGet("Path").ToString(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			log.Loggers = append(log.Loggers, f)
			log.Println("sys", "File Logger Registered", file.MustGet("Path").ToString())
		}

		if udp, err := logger.Get("UDPLogger"); err == nil {
			log.Loggers = append(log.Loggers, NewUdpLogger(udp.MustGet("Addr").ToString()))
			log.Println("sys", "UDP Logger Registered", udp.MustGet("Addr").ToString())
		}
	}
	return nil
}
