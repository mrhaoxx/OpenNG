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

func (l *loggers) Add(logger Logger) {
	for _, existing := range l.Loggers {
		if existing == logger {
			return
		}
	}
	l.Loggers = append(l.Loggers, logger)
}

func (l *loggers) Set(loggers []Logger) {
	l.Loggers = loggers
}

func (l *loggers) Reset() {
	l.Loggers = []Logger{}
}

var Loggers = &loggers{[]Logger{os.Stdout}}
