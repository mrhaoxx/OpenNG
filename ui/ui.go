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
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	utils "github.com/mrhaoxx/OpenNG/utils"
)

//go:embed html/dist
var index embed.FS

//go:embed html/connections.html
var html_connection string

//go:embed html/requests.html
var html_requests string

type Reporter interface {
	Report() map[uint64]interface{}
}

var ConfigFile string

type UI struct {
	TcpController Reporter
	HttpMidware   Reporter
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
		ctx.WriteString(html_connection)
	case "/requests":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		ctx.WriteString(html_requests)
	case "/logs":
		Sselogger.ServeHTTP(ctx.Resp, ctx.Req)
	case "/restart":
		ctx.Resp.ErrorPage(http.StatusNotImplemented, "Not Implemented")

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
		os.WriteFile(ConfigFile, b, fs.ModeCharDevice)
		ctx.Resp.WriteHeader(http.StatusAccepted)
	case "/api/v1/cfg/get":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := os.ReadFile(ConfigFile)
		ctx.Resp.Write(b)
	case "/api/v1/cfg/getcur":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(curcfg)

	case "/api/v1/cfg/schema":
		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(GenerateJsonSchema())

	case "/genhash":
		b, _ := io.ReadAll(ctx.Req.Body)
		hashed, _ := utils.HashPassword(string(b))
		ctx.Resp.Write([]byte(hashed))

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
			log.Println("sys", "the server is going down in 1 second")
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

var Sselogger = utils.NewTextStreamLogger()

func Reload() error {
	r, err := os.ReadFile(ConfigFile)

	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	if err := LoadCfg(r, true); err != nil {
		return err
	}

	return nil
}
