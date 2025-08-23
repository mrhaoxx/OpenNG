package log

import (
	"os"
)

type Logger interface {
	Write([]byte) (int, error)
}

type loggers struct {
	Loggers []Logger
}

func (l *loggers) Write(p []byte) (n int, err error) {
	for _, logger := range l.Loggers {
		logger.Write(p)
	}
	return len(p), nil
}

var Loggers = &loggers{[]Logger{os.Stdout}}
