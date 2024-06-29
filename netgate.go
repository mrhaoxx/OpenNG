package main

import (
	"fmt"
	"os"
	"runtime"

	_ "github.com/mrhaoxx/OpenNG/auth"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/ui"
)

func main() {
	log.Println(`NetGATE - HomeLab Inbound Gateway
 _   _      _    ____    _  _____ _____ 
| \ | | ___| |_ / ___|  / \|_   _| ____|
|  \| |/ _ \ __| |  _  / _ \ | | |  _|  
| |\  |  __/ |_| |_| |/ ___ \| | | |___ 
|_| \_|\___|\__|\____/_/   \_\_| |_____|
`, gitver, buildstamp, runtime.GOOS, runtime.Version(), runtime.GOARCH)

	if os.Args[len(os.Args)-1] == "version" {
		return
	}
	r, err := os.ReadFile("new.config.yaml")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if err := ui.LoadCfgV2(r); err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	log.Println("sys", "Loaded")
	select {}
}
