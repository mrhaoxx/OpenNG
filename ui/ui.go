package ui

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	stdhttp "net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	auth "github.com/mrhaoxx/OpenNG/auth"
	http "github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	utils "github.com/mrhaoxx/OpenNG/utils"

	"github.com/dlclark/regexp2"
)

//go:embed html/ace.js
var acejs string

//go:embed html/yaml.js
var yamljs string

//go:embed html/index.html
var html_index string

//go:embed html/connections.html
var html_connection string

//go:embed html/requests.html
var html_requests string

//go:embed html/config.html
var html_config string

//go:embed html/cards.js
var js_cards string

type UI struct {
}

func (*UI) Hosts() utils.GroupRegexp {
	return nil
}
func (*UI) HandleHTTP(ctx *http.HttpCtx) http.Ret {
	switch ctx.Req.URL.Path {
	case "/ace.js":
		ctx.Resp.Header().Add("Content-Type", "text/javascript; charset=utf-8")
		ctx.Resp.Header().Add("Cache-Control", "public")
		ctx.WriteString(acejs)
	case "/yaml.js":
		ctx.Resp.Header().Add("Content-Type", "text/javascript; charset=utf-8")
		ctx.Resp.Header().Add("Cache-Control", "public")
		ctx.WriteString(yamljs)
	case "/cards.js":
		ctx.Resp.Header().Add("Content-Type", "text/javascript; charset=utf-8")
		// ctx.Resp.Header().Add("Cache-Control", "public")
		bytes, _ := os.ReadFile("ui/html/cards.js")
		ctx.Resp.Write(bytes)
	case "/":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		ctx.WriteString(html_index)
	case "/config":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		bytes, _ := os.ReadFile("ui/html/config.html")
		ctx.Resp.Write(bytes)
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
	case "/cfg/apply":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		LoadCfg(b)
		ctx.Resp.WriteHeader(http.StatusAccepted)
	case "/cfg/save":
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		os.WriteFile("config.yaml", b, fs.ModeCharDevice)
		ctx.Resp.WriteHeader(http.StatusAccepted)
	case "/cfg/get":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(curcfg)
	case "/genhash":
		b, _ := io.ReadAll(ctx.Req.Body)
		hashed := auth.GenHash(string(b))
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
			res := TcpController.ReportActiveConnections()
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
	case "/api/v1/tcp/connection/kill": //POST FORM: cid uint64 (ConnectionID)
		if ctx.Req.Method == "POST" {
			ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")

			id, err := strconv.ParseUint(ctx.Req.PostFormValue("cid"), 10, 64)
			if err != nil {
				ctx.Resp.WriteHeader(http.StatusBadRequest)
				ctx.Resp.Write([]byte(err.Error()))
			} else {
				err = TcpController.KillConnection(id)
				if err != nil {
					ctx.Resp.WriteHeader(http.StatusBadRequest)
					ctx.Resp.Write([]byte(err.Error()))
				} else {
					ctx.Resp.WriteHeader(http.StatusOK)
				}
			}
		} else {
			ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
		}
	case "/api/v1/http/requests": //GET json output
		if ctx.Req.Method == "GET" {
			ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")
			res := HttpMidware.ReportActiveRequests()
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
	case "/api/v1/http/request/kill":
		if ctx.Req.Method == "POST" {
			ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")

			id, err := strconv.ParseUint(ctx.Req.PostFormValue("rid"), 10, 64)
			if err != nil {
				ctx.Resp.WriteHeader(http.StatusBadRequest)
				ctx.Resp.Write([]byte(err.Error()))
			} else {
				err = HttpMidware.KillRequest(id)
				if err != nil {
					ctx.Resp.WriteHeader(http.StatusBadRequest)
					ctx.Resp.Write([]byte(err.Error()))
				} else {
					ctx.Resp.WriteHeader(http.StatusOK)
				}
			}
		} else {
			ctx.Resp.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
		}
	// case "/api/v1/auth/sessions":
	// 	if ctx.Req.Method == "GET" {
	// 		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
	// 		ctx.Resp.Header().Set("Cache-Control", "no-cache")
	// 		res := Auth.ReportActiveSessions()
	// 		byt, err := json.Marshal(res)
	// 		if err != nil {
	// 			ctx.Resp.WriteHeader(http.StatusInternalServerError)
	// 			ctx.Resp.Write([]byte(err.Error()))
	// 		} else {
	// 			ctx.Resp.Write(byt)
	// 		}
	// 	} else {
	// 		ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
	// 	}
	// case "/api/v1/auth/users":
	// 	if ctx.Req.Method == "GET" {
	// 		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
	// 		ctx.Resp.Header().Set("Cache-Control", "no-cache")
	// 		res := Auth.ReportUsers()
	// 		byt, err := json.Marshal(res)
	// 		if err != nil {
	// 			ctx.Resp.WriteHeader(http.StatusInternalServerError)
	// 			ctx.Resp.Write([]byte(err.Error()))
	// 		} else {
	// 			ctx.Resp.Write(byt)
	// 		}
	// 	} else {
	// 		ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
	// 	}
	// case "/api/v1/auth/policies":
	// 	if ctx.Req.Method == "GET" {
	// 		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
	// 		ctx.Resp.Header().Set("Cache-Control", "no-cache")
	// 		res := Auth.ReportPolicies()
	// 		byt, err := json.Marshal(res)
	// 		if err != nil {
	// 			ctx.Resp.WriteHeader(http.StatusInternalServerError)
	// 			ctx.Resp.Write([]byte(err.Error()))
	// 		} else {
	// 			ctx.Resp.Write(byt)
	// 		}
	// 	} else {
	// 		ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
	// 	}
	default:
		if strings.HasPrefix(ctx.Req.URL.Path, "/debug/pprof") {
			stdhttp.DefaultServeMux.ServeHTTP(ctx.Resp, ctx.Req)

		} else {
			ctx.Resp.ErrorPage(http.StatusNotFound, "Not Found")
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
