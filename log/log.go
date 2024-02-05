package log

import (
	"fmt"
	"os"
	"time"
)

type Logger interface {
	Write([]byte) (int, error)
}

var loggers = []Logger{os.Stdout}

func RegisterLogger(_loggers ...Logger) {
	loggers = append(loggers, _loggers...)
}

func Println(msgs ...any) {
	var t = time.Now().UTC()
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

func ClearLoggers() {
	loggers = []Logger{}
}
