package logging

import (
	"fmt"
	"os"
	"time"
)

type Logger interface {
	Write([]byte) (int, error)
}

var loggers = []Logger{}

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

type LoggerConfig struct {
	UDP UdpLoggerConfig `yaml:"UdpLogger"`
	// Influx         InfluxConfig    `yaml:"Influx"`
	EnableSSE      bool   `yaml:"EnableSSE"`
	File           string `yaml:"File"`
	DisableConsole bool   `yaml:"DisableConsole"`
}

func Load(cfg LoggerConfig) {
	if cfg.DisableConsole {
		Println("sys", "Disabling Console Logging")
		loggers = make([]Logger, 0)
	}
	if cfg.File != "" {
		f, _ := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		RegisterLogger(f)
		Println("sys", "File Logger Registered", cfg.File)
	}
	if cfg.UDP.Address != "" {
		RegisterLogger(NewUdpLogger(cfg.UDP))
		Println("sys", "UDP Logger Registered", cfg.UDP.Address)
	}
	// if cfg.Influx.Url != "" {
	// 	RegisterLogger(NewInfluxLogger(cfg.Influx))
	// 	Println("sys", "Influx DB Registered", cfg.Influx.Url, cfg.Influx.Org, cfg.Influx.Bucket)
	// }

}
