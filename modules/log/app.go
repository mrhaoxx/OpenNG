package log

import (
	"fmt"
	"os"
)

func SetupOutputs(outputs []string) error {
	if len(outputs) == 0 {
		return nil
	}
	var loggers []Logger
	for _, out := range outputs {
		switch out {
		case "stdout":
			loggers = append(loggers, os.Stdout)
		case "stderr":
			loggers = append(loggers, os.Stderr)
		default:
			f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("cannot open log file %q: %w", out, err)
			}
			loggers = append(loggers, f)
		}
	}
	Loggers.Set(loggers)
	return nil
}
