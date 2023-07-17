package ui

import (
	_ "embed"
	"encoding/json"
	"io"
	"io/fs"
	stdhttp "net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"

	http "github.com/haoxingxing/OpenNG/http"
	utils "github.com/haoxingxing/OpenNG/utils"

	"github.com/dlclark/regexp2"
)

//go:embed html/ace.js
var acejs string

//go:embed html/index.html
var html_index string

//go:embed html/connections.html
var html_connection string

//go:embed html/requests.html
var html_requests string

type UI struct {
}

func (*UI) Hosts() []*regexp2.Regexp {
	return nil
}
func (*UI) HandleHTTP(ctx *http.HttpCtx) http.Ret {
	switch ctx.Req.URL.Path {
	case "/ace.js":
		ctx.Resp.Header().Add("Content-Type", "text/javascript; charset=utf-8")
		ctx.Resp.Header().Add("Cache-Control", "public")
		ctx.WriteString(acejs)
	case "/":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		ctx.WriteString(html_index)
	case "/connections":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		ctx.WriteString(html_connection)
	case "/requests":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		ctx.WriteString(html_requests)
	case "/logs":
		Sselogger.ServeHTTP(ctx.Resp, ctx.Req)
	case "/restart":
		utils.Restart()
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
	// case "/genhash":
	// 	b, _ := io.ReadAll(ctx.Req.Body)
	// 	hashed := auth.GenHash(string(b))
	// 	ctx.Resp.Write([]byte(hashed))

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
			ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
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
			ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
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
			ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
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
			ctx.ErrorPage(http.StatusMethodNotAllowed, "Method not allowed")
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
			ctx.ErrorPage(http.StatusNotFound, "Not Found")
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
