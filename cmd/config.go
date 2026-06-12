package ngcmd

import (
	"fmt"
	"os"
	"time"

	ng "github.com/mrhaoxx/OpenNG"
	nglog "github.com/mrhaoxx/OpenNG/modules/log"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

var CurSpace *ng.Space

func LoadCfg(cfgs []byte, reload bool) error {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}

	nodes := &ng.ArgNode{}

	err = nodes.FromAny(cfg)
	if err != nil {
		return err
	}

	if err := Dedref(nodes); err != nil {
		return err
	}

	if err := ng.AssertArg(nodes, TopLevelConfigAssertion); err != nil {
		return err
	}

	if !reload {
		err = GlobalCfg(nodes.MustGet("Config"))

		if err != nil {
			return err
		}
	}

	space := ng.Space{
		Services: map[string]any{
			"sys": &ngnet.SysInterface{},
		},
		Refs:         ng.Registry(),
		AssertRefs:   ng.AssertionsRegistry(),
		ServiceKinds: map[string]string{},
	}

	space.Services["@"] = space

	err = space.Apply(nodes, reload, false)

	if err == nil {
		old := CurSpace
		CurSpace = &space
		if old != nil {
			old.Stop()
		}
	} else if reload {
		// The half-built generation may already hold resources (it steals
		// listeners from the running one on rebind); retire it instead of
		// leaking it. Ports it took over stay down until the next
		// successful reload.
		space.Stop()
	}

	return err
}

func GlobalCfg(config *ng.ArgNode) error {

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
		outputs := logger.MustGet("Outputs").ToStringList()
		if err := nglog.SetupOutputs(outputs); err != nil {
			return err
		}
	}
	return nil
}

func ValidateCfg(cfgs []byte) []ng.ConfigError {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return []ng.ConfigError{{Phase: "parse", Message: err.Error()}}
	}

	nodes := &ng.ArgNode{}
	if err := nodes.FromAny(cfg); err != nil {
		return []ng.ConfigError{{Phase: "parse", Message: err.Error()}}
	}

	if err := Dedref(nodes); err != nil {
		return []ng.ConfigError{{Phase: "parse", Message: err.Error()}}
	}

	if err := ng.AssertArg(nodes, TopLevelConfigAssertion); err != nil {
		return []ng.ConfigError{{Phase: "schema", Message: err.Error()}}
	}

	space := ng.Space{
		Services:     map[string]any{"sys": true},
		Refs:         ng.Registry(),
		AssertRefs:   ng.AssertionsRegistry(),
		ServiceKinds: map[string]string{},
	}

	return space.Validate(nodes)
}
