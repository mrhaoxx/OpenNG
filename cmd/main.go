package netgatecmd

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/log"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

var Configfile = flag.String("config", "config.yaml", "the config file to load")
var printversion = flag.Bool("version", false, "print version and exit")
var helpmessage = flag.Bool("help", false, "print help message")
var printjsonschema = flag.Bool("jsonschema", false, "print json schema to stdout")

func Main() {

	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.DurationFieldUnit = time.Second
	zlog.Logger = zlog.Output(log.Loggers)

	// zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339Nano})

	fmt.Fprintf(os.Stderr, "NetGATE - A Inbound Gateway\n")
	flag.Parse()

	if *helpmessage {
		flag.PrintDefaults()
		return
	}
	binaryInfo, _ := debug.ReadBuildInfo()

	vcs := "unknown"
	for _, s := range binaryInfo.Settings {
		if s.Key == "vcs.revision" {
			vcs = s.Value
			break
		}
	}

	fmt.Fprintf(os.Stderr, `
 _   _      _    ____    _  _____ _____ 
| \ | | ___| |_ / ___|  / \|_   _| ____|
|  \| |/ _ \ __| |  _  / _ \ | | |  _|  
| |\  |  __/ |_| |_| |/ ___ \| | | |___ 
|_| \_|\___|\__|\____/_/   \_\_| |_____|

%s %s 
%s %s %s %s

config: %s

`,
		vcs, binaryInfo.Main.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler, *Configfile)

	switch {
	case *printjsonschema:
		os.Stdout.Write(netgate.GenerateJsonSchema())
		return
	case *printversion:
		return
	}
	r, err := os.ReadFile(*Configfile)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	_start := time.Now()

	if err := LoadCfg(r, false); err != nil {
		zlog.Error().
			Str("type", "sys/config").
			Str("error", err.Error()).
			Msg("configuration load failed")
		os.Exit(-1)
	}

	fmt.Fprintf(os.Stderr, "configuration from %s loaded in %s\n", *Configfile, time.Since(_start).String())
	select {}
}
