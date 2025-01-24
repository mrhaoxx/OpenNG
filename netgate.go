package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	_ "github.com/mrhaoxx/OpenNG/auth"
	_ "github.com/mrhaoxx/OpenNG/init"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/ui"
)

var gitver = "dev"
var buildstamp = "dev-built"

var configfile = flag.String("config", "config.yaml", "the config file to load")
var printversion = flag.Bool("version", false, "print version and exit")
var helpmessage = flag.Bool("help", false, "print help message")
var printjsonschema = flag.Bool("jsonschema", false, "print json schema to stdout")

func main() {
	fmt.Fprintf(os.Stderr, "NetGATE - A Inbound Gateway\n")
	flag.Parse()

	if *helpmessage {
		flag.PrintDefaults()
		return
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
		gitver, buildstamp, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler, *configfile)

	switch {
	case *printjsonschema:
		os.Stdout.Write(ui.GenerateJsonSchema())
		return
	case *printversion:
		return
	}
	r, err := os.ReadFile(*configfile)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ui.ConfigFile = *configfile

	_start := time.Now()

	if err := ui.LoadCfg(r, false); err != nil {
		log.Println(err)
		os.Exit(-1)
	}

	fmt.Fprintf(os.Stderr, "configuration from %s loaded in %s\n", *configfile, time.Since(_start).String())
	select {}
}
