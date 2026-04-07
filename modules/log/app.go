package log

import (
	"fmt"
	"os"
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
)

func init() {
	ng.Register("log::stdout",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.TypeOf[Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			return os.Stdout, nil
		},
	)
	ng.Register("log::stderr",
		ng.Assert{Type: "null"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.TypeOf[Logger]()}},
		func(an *ng.ArgNode) (any, error) {
			return os.Stderr, nil
		},
	)

	ng.Register("log::file",
		ng.Assert{Type: "string"},
		ng.Assert{Type: "ptr", Impls: []reflect.Type{ng.TypeOf[Logger]()}},
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
