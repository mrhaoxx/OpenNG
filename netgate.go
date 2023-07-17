package main

import (
	_ "github.com/haoxingxing/OpenNG/auth"
	"github.com/haoxingxing/OpenNG/logging"
	"github.com/haoxingxing/OpenNG/ui"
	"fmt"
	"os"
	"runtime"
)

func main() {
	logging.RegisterLogger(os.Stdout)

	logging.Println(`NetGATE - HomeLab Inbound Gateway
 _   _      _    ____    _  _____ _____ 
| \ | | ___| |_ / ___|  / \|_   _| ____|
|  \| |/ _ \ __| |  _  / _ \ | | |  _|  
| |\  |  __/ |_| |_| |/ ___ \| | | |___ 
|_| \_|\___|\__|\____/_/   \_\_| |_____|
`, gitver, buildstamp, runtime.GOOS, runtime.Version(), runtime.GOARCH)

	if os.Args[len(os.Args)-1] == "version" {
		return
	}
	r, err := os.ReadFile("config.yaml")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if err := ui.LoadCfg(r); err != nil {
		logging.Println(err)
		os.Exit(-1)
	}
	logging.Println("sys", "Loaded")
	select {}
}
