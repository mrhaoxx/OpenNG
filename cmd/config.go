package netgatecmd

import (
	"fmt"
	"os"
	"time"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/net"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

func LoadCfg(cfgs []byte, reload bool) error {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}

	nodes := &netgate.ArgNode{}

	err = nodes.FromAny(cfg)
	if err != nil {
		return err
	}

	if err := Dedref(nodes); err != nil {
		return err
	}

	if err := AssertArg(nodes, TopLevelConfigAssertion); err != nil {
		return err
	}

	if !reload {
		err = GlobalCfg(nodes.MustGet("Config"))

		if err != nil {
			return err
		}
	}

	space := Space{
		Services: map[string]any{
			"sys": &net.SysInterface{},
		},
		Refs:       netgate.Registry(),
		AssertRefs: netgate.AssertionsRegistry(),
	}

	space.Services["@"] = space

	err = space.Apply(nodes, reload)

	return err
}

func GlobalCfg(config *netgate.ArgNode) error {

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
	}
	return nil
}

func ValidateCfg(cfgs []byte) []string {
	var cfg any
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return []string{err.Error()}
	}

	nodes := &netgate.ArgNode{}
	err = nodes.FromAny(cfg)
	if err != nil {
		return []string{err.Error()}
	}

	if err := Dedref(nodes); err != nil {
		return []string{err.Error()}
	}

	if err := AssertArg(nodes, TopLevelConfigAssertion); err != nil {
		return []string{err.Error()}
	}

	space := Space{
		Services: map[string]any{
			"sys": true,
		},
		Refs:       netgate.Registry(),
		AssertRefs: netgate.AssertionsRegistry(),
	}

	errs := []string{}

	errors := space.Validate(nodes)

	if len(errors) > 0 {
		for _, err := range errors {
			errs = append(errs, err.Error())
		}
		return errs
	}

	return nil
}
