package log

import (
	"fmt"
	"os"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/log"
)

func init() {
	ng.Register("log::add",
		ng.Assert{Type: "ptr"},
		ng.Assert{Type: "null"},
		func(an *ng.ArgNode) (any, error) {
			logger, ok := an.Value.(log.Logger)
			if !ok {
				return nil, fmt.Errorf("argument is not a log.Logger")
			}
			log.Loggers.Add(logger)
			return nil, nil
		},
	)

	ng.Register("log::set",
		ng.Assert{
			Type: "list",
			Sub: ng.AssertMap{
				"_": {Type: "ptr"},
			},
		},
		ng.Assert{Type: "null"},
		func(an *ng.ArgNode) (any, error) {
			logger := an.ToList()

			loggers := []log.Logger{}

			for i, l := range logger {
				lg, ok := l.Value.(log.Logger)
				if !ok {
					return nil, fmt.Errorf("item %d is not a log.Logger", i)
				}
				loggers = append(loggers, lg)
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
		ng.Assert{Type: "ptr"},
		func(an *ng.ArgNode) (any, error) {
			return os.Stdout, nil
		},
	)
	ng.Register("log::stderr",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr"},
		func(an *ng.ArgNode) (any, error) {
			return os.Stderr, nil
		},
	)

	ng.Register("log::file",
		ng.Assert{Type: "string"},
		ng.Assert{Type: "ptr"},
		func(an *ng.ArgNode) (any, error) {
			path, ok := an.Value.(string)
			if !ok {
				return nil, fmt.Errorf("argument is not a string")
			}
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return nil, fmt.Errorf("cannot open log file: %v", err)
			}
			return f, nil
		},
	)

}
