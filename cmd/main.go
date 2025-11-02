package netgatecmd

import (
	"encoding/json"
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
		os.Stdout.Write(GenerateJsonSchema())
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

func GenerateJsonSchema() []byte {
	refs_assertions := netgate.AssertionsRegistry()

	root := ToScheme(TopLevelConfigAssertion, 0, 5).(map[string]any)

	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"

	services := root["properties"].(map[string]any)["Services"].(map[string]any)["items"].(map[string]any)

	allOf := []any{}

	for k, v := range refs_assertions {

		if k == "_" {
			continue
		}

		allOf = append(allOf, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"kind": map[string]any{
						"const": k,
					},
				},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"spec": ToScheme(v, 0, 5),
				},
				"description": v.Desc,
			},
		})
	}

	if len(allOf) > 0 {
		services["allOf"] = allOf
	}

	s, _ := json.Marshal(root)

	return s
}
