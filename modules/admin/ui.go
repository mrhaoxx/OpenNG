package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	stdhttp "net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	netgatecmd "github.com/mrhaoxx/OpenNG/cmd"
	"github.com/mrhaoxx/OpenNG/modules/http"
	"github.com/mrhaoxx/OpenNG/modules/tls"
	"github.com/mrhaoxx/OpenNG/utils"
	zlog "github.com/rs/zerolog/log"

	file "github.com/mrhaoxx/OpenNG/modules/auth/backend"
)

//go:embed html/dist
var index embed.FS

type Reporter interface {
	Report() map[string]interface{}
}

var Uptime time.Time = time.Now()
var ReloadTime time.Time = time.Now()
var ReloadCount int = 0

type UI struct {
	TcpController Reporter
	HttpMidware   Reporter

	TlsMgr *tls.TlsMgr
}

func (*UI) Hosts() utils.GroupRegexp {
	return nil
}
func (u *UI) HandleHTTP(ctx *http.HttpCtx) http.Ret {
	switch ctx.Req.URL.Path {

	case "/":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist/index.html")
	case "/connections":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist/connections.html")
	case "/requests":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist/requests.html")
	case "/logs":
		Sselogger.ServeHTTP(ctx.Resp, ctx.Req)
	case "/restart":
		ctx.Resp.ErrorPage(http.StatusNotImplemented, "Not Implemented")

	case "/api/v1/tls/reload":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		if u.TlsMgr != nil {
			err := u.TlsMgr.Reload()
			if err != nil {
				ctx.Resp.WriteHeader(http.StatusBadRequest)
				ctx.WriteString(err.Error())
			} else {
				ctx.Resp.WriteHeader(http.StatusAccepted)
			}
		} else {
			ctx.Resp.WriteHeader(http.StatusFailedDependency)
			ctx.WriteString("TlsMgr not set")
		}

	case "/api/v1/cfg/reload":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		err := Reload()
		if err != nil {
			ctx.Resp.WriteHeader(http.StatusBadRequest)
			ctx.WriteString(err.Error())
		} else {
			ctx.Resp.WriteHeader(http.StatusAccepted)
		}
	case "/api/v1/cfg/save":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		errors := netgatecmd.ValidateCfg(b)
		if len(errors) > 0 {
			ctx.Resp.WriteHeader(http.StatusNotAcceptable)
			ctx.WriteString(strings.Join(errors, "\n"))
			return http.RequestEnd
		}
		os.WriteFile(*netgatecmd.Configfile, b, fs.ModeCharDevice)
		ctx.Resp.WriteHeader(http.StatusAccepted)
	case "/api/v1/cfg/validate":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		errors := netgatecmd.ValidateCfg(b)
		ctx.Resp.WriteHeader(http.StatusAccepted)
		if len(errors) > 0 {
			ctx.WriteString(strings.Join(errors, "\n"))
		} else {
			ctx.WriteString("ok")
		}
	case "/api/v1/cfg/get":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := os.ReadFile(*netgatecmd.Configfile)
		ctx.Resp.Write(b)
	case "/api/v1/cfg/getcur":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(curcfg)

	case "/api/v1/cfg/schema":
		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(netgatecmd.GenerateJsonSchema())

	case "/genhash":
		b, _ := io.ReadAll(ctx.Req.Body)
		hashed, _ := file.HashPassword(string(b))
		ctx.Resp.Write([]byte(hashed))
	case "/api/v1/uptime":
		ctx.WriteString(fmt.Sprint(
			"uptime: ", time.Since(Uptime).Round(time.Second), "\n",
		))

	case "/sys":
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		ctx.WriteString(fmt.Sprint("alloc: ", m.Alloc, "\n",
			"totalalloc: ", m.TotalAlloc, "\n",
			"sysmem: ", m.Sys, "\n",
			"numgc: ", m.NumGC, "\n",
			"goroutines: ", runtime.NumGoroutine(), "\n",
			"cpus: ", runtime.NumCPU(), "\n",
			"ccalls: ", runtime.NumCgoCall(), "\n",
		))

	case "/shutdown":
		ctx.Resp.WriteHeader(http.StatusAccepted)
		go func() {
			zlog.Warn().
				Str("type", "sys").
				Msg("the server is going down in 1 second")
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()

	case "/204":
		ctx.Resp.WriteHeader(204)

	case "/api/v1/tcp/connections": //GET json output
		if ctx.Req.Method == "GET" {
			ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")
			res := u.TcpController.Report()
			byt, err := json.Marshal(res)
			if err != nil {
				ctx.Resp.WriteHeader(http.StatusInternalServerError)
				ctx.Resp.Write([]byte(err.Error()))
			} else {
				ctx.Resp.Write(byt)
			}
		} else {
			ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
		}

	case "/api/v1/http/requests": //GET json output
		if ctx.Req.Method == "GET" {
			ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")
			res := u.HttpMidware.Report()
			byt, err := json.Marshal(res)
			if err != nil {
				ctx.Resp.WriteHeader(http.StatusInternalServerError)
				ctx.Resp.Write([]byte(err.Error()))
			} else {
				ctx.Resp.Write(byt)
			}
		} else {
			ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
		}

	default:
		if strings.HasPrefix(ctx.Req.URL.Path, "/debug/pprof") {
			stdhttp.DefaultServeMux.ServeHTTP(ctx.Resp, ctx.Req)
		} else {
			stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist"+ctx.Req.URL.Path)
		}
	}
	return http.RequestEnd
}
func (*UI) HandleHTTPInternal(ctx *http.HttpCtx) http.Ret {
	return http.RequestEnd
}

func (*UI) PathsInternal() []*regexp2.Regexp {
	return nil
}

var curcfg []byte

var Sselogger = NewTextStreamLogger()

func Reload() error {

	ReloadTime = time.Now()
	ReloadCount++

	r, err := os.ReadFile(*netgatecmd.Configfile)

	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	if err := netgatecmd.LoadCfg(r, true); err != nil {
		return err
	}

	return nil
}
