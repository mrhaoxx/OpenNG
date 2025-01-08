package init

import (
	"os"
	"strings"
)

func init() {

	goDebug := os.Getenv("GODEBUG")
	if strings.Contains(goDebug, "http2xconnect") {
		return
	}

	if len(goDebug) > 0 {
		goDebug += ","
	}
	os.Setenv("GODEBUG", goDebug+"http2xconnect=0")
}
