package log

import (
	"fmt"
	"os"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/log"
)

func init() {
	ng.Register("log::add",
		ng.Assert{Type: "ptr", Impls: []reflect.Type{
			ng.Iface[log.Logger](),
		}},
		ng.Assert{Type: "null"},
		func(an *ng.ArgNode) (any, error) {
			log.Loggers.Add(an.Value.(log.Logger))
			return nil, nil
		},
	)

	ng.Register("log::set",
		ng.Assert{
			Type: "list",
			Sub: ng.AssertMap{
				"_": {Type: "ptr", Impls: []reflect.Type{ng.Iface[log.Logger]()}},
			},
		},
		ng.Assert{Type: "null"},
		func(an *ng.ArgNode) (any, error) {
			logger := an.ToList()

			loggers := []log.Logger{}

			for _, l := range logger {
				loggers = append(loggers, l.Value.(log.Logger))
			}

			log.Loggers.Set(loggers)
			return nil, nil
		},
	)

	ng.Register("log::reset",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "null"},
		func(an *ng.ArgNode) (any, error) {
			log.Loggers.Reset()
			return nil, nil
		},
	)

	ng.Register("log::stdout",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.Iface[log.Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			return os.Stdout, nil
		},
	)
	ng.Register("log::stderr",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.Iface[log.Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			return os.Stderr, nil
		},
	)

	ng.Register("log::file",
		ng.Assert{Type: "string"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.Iface[log.Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			path := an.ToString()
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return nil, fmt.Errorf("cannot open log file: %v", err)
			}
			return f, nil
		},
	)

}
