package log

import (
	"fmt"
	"os"

	"github.com/mrhaoxx/OpenNG/config"
	"github.com/mrhaoxx/OpenNG/log"
)

func init() {
	config.Register("log::add", func(an *config.ArgNode) (any, error) {
		logger, ok := an.Value.(log.Logger)
		if !ok {
			return nil, fmt.Errorf("argument is not a log.Logger")
		}
		log.Loggers.Add(logger)
		return nil, nil
	}, config.Assert{
		Type: "ptr",
	})

	config.Register("log::set", func(an *config.ArgNode) (any, error) {
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
	}, config.Assert{
		Type: "list",
		Sub: config.AssertMap{
			"_": {Type: "ptr"},
		},
	})

	config.Register("log::reset", func(an *config.ArgNode) (any, error) {
		log.Loggers.Reset()
		return nil, nil
	}, config.Assert{
		Type: "null",
	})

	config.Register("log::stdout", func(an *config.ArgNode) (any, error) {
		return os.Stdout, nil
	}, config.Assert{
		Type: "null",
	})
	config.Register("log::stderr", func(an *config.ArgNode) (any, error) {
		return os.Stderr, nil
	}, config.Assert{
		Type: "null",
	})

	config.Register("log::file", func(an *config.ArgNode) (any, error) {
		path, ok := an.Value.(string)
		if !ok {
			return nil, fmt.Errorf("argument is not a string")
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("cannot open log file: %v", err)
		}
		return f, nil
	}, config.Assert{
		Type: "string",
	})

}
