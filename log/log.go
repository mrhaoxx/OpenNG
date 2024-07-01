package log

import (
	"fmt"
	"os"
	"time"
)

type Logger interface {
	Write([]byte) (int, error)
}

var Loggers = []Logger{os.Stdout}

var TZ = time.Local

var Verb = false

func println(loggers []Logger, msgs ...any) {
	var t = time.Now().In(TZ)
	var buf []byte
	year, month, day := t.Date()
	itoa(&buf, year, 4)
	buf = append(buf, '-')
	itoa(&buf, int(month), 2)
	buf = append(buf, '-')
	itoa(&buf, day, 2)
	buf = append(buf, ' ')
	hour, min, sec := t.Clock()
	itoa(&buf, hour, 2)
	buf = append(buf, ':')
	itoa(&buf, min, 2)
	buf = append(buf, ':')
	itoa(&buf, sec, 2)
	buf = append(buf, '.')
	itoa(&buf, t.Nanosecond()/1e3, 6)
	buf = append(buf, ' ')

	for _, logger := range loggers {
		logger.Write(fmt.Appendln(buf, msgs...))
	}
}

func Println(msgs ...any) {
	println(Loggers, msgs...)
}

func Verboseln(msgs ...any) {
	if Verb {
		println(Loggers, append(append([]any{"\033[90m[verb]"}, msgs...), "\033[0m")...)
	}
}

func itoa(buf *[]byte, i int, wid int) {
	// Assemble decimal in reverse order.
	var b [20]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	b[bp] = byte('0' + i)
	*buf = append(*buf, b[bp:]...)
}
