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

	if reload && !ngnet.SupportsListenerHandoff && CurSpace != nil {
		// No SO_REUSEPORT: the new generation cannot co-bind, so release
		// the old generation's listeners before applying the new config.
		// This leaves a brief window where the addresses are unbound and,
		// if Apply fails, the old generation is already gone — the
		// platform tradeoff for not stealing ports.
		CurSpace.Stop()
		CurSpace = nil
	}

	err = space.Apply(nodes, reload, false)

	if err == nil {
		old := CurSpace
		CurSpace = &space
		if old != nil {
			// Handoff platforms: the new generation already co-bound, so
			// retiring the old one now completes a gapless cutover.
			old.Stop()
		}
	} else if reload {
		// Retire the half-built generation instead of leaking it. On
		// handoff platforms its addresses fall back to the still-running
		// old generation via SO_REUSEPORT; dns/wireguard cut over at
		// construction time.
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
