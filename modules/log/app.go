package log

import (
	"fmt"
	"os"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/log"
)

func init() {
	netgate.Register("log::add", func(an *netgate.ArgNode) (any, error) {
		logger, ok := an.Value.(log.Logger)
		if !ok {
			return nil, fmt.Errorf("argument is not a log.Logger")
		}
		log.Loggers.Add(logger)
		return nil, nil
	}, netgate.Assert{
		Type: "ptr",
	})

	netgate.Register("log::set", func(an *netgate.ArgNode) (any, error) {
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
	}, netgate.Assert{
		Type: "list",
		Sub: netgate.AssertMap{
			"_": {Type: "ptr"},
		},
	})

	netgate.Register("log::reset", func(an *netgate.ArgNode) (any, error) {
		log.Loggers.Reset()
		return nil, nil
	}, netgate.Assert{
		Type: "null",
	})

	netgate.Register("log::stdout", func(an *netgate.ArgNode) (any, error) {
		return os.Stdout, nil
	}, netgate.Assert{
		Type: "null",
	})
	netgate.Register("log::stderr", func(an *netgate.ArgNode) (any, error) {
		return os.Stderr, nil
	}, netgate.Assert{
		Type: "null",
	})

	netgate.Register("log::file", func(an *netgate.ArgNode) (any, error) {
		path, ok := an.Value.(string)
		if !ok {
			return nil, fmt.Errorf("argument is not a string")
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("cannot open log file: %v", err)
		}
		return f, nil
	}, netgate.Assert{
		Type: "string",
	})

}
