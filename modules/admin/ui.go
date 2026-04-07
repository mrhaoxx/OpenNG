package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	ng "github.com/mrhaoxx/OpenNG"
	ngcmd "github.com/mrhaoxx/OpenNG/cmd"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
	zlog "github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

//go:embed html/dist
var index embed.FS

var cachedSchema []byte

var Uptime time.Time = time.Now()
var ReloadTime time.Time = time.Now()
var ReloadCount int = 0

type UI struct {
}

type apiCallResponse struct {
	Success bool        `json:"success"`
	Result  interface{} `json:"result,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (*UI) Hosts() groupexp.GroupRegexp {
	return nil
}
func (u *UI) HandleHTTP(ctx *nghttp.HttpCtx) nghttp.Ret {
	if isSafeHTTPMethod(ctx.Req.Method) {
		ensureCSRFCookie(ctx)
	} else {
		if !requireCSRF(ctx) {
			return nghttp.RequestEnd
		}
	}
	// Instance API routing
	if strings.HasPrefix(ctx.Req.URL.Path, "/api/v1/instance/") {
		rest := strings.TrimPrefix(ctx.Req.URL.Path, "/api/v1/instance/")
		slashIdx := strings.Index(rest, "/")
		if slashIdx == -1 {
			// GET /api/v1/instance/{name} — instance detail
			instanceName := rest
			u.handleInstanceDetail(ctx, instanceName)
			return nghttp.RequestEnd
		}
		instanceName := rest[:slashIdx]
		subPath := rest[slashIdx:] // e.g., "/connections"
		if u.handleInstanceRoute(ctx, instanceName, subPath) {
			return nghttp.RequestEnd
		}
		ctx.Resp.ErrorPage(404, "route not found")
		return nghttp.RequestEnd
	}

	switch ctx.Req.URL.Path {

	case "/":
		ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
		stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist/index.html")
	case "/logs":
		Sselogger.ServeHTTP(ctx.Resp, ctx.Req)

	case "/api/v1/cfg/reload":
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		err := Reload()
		if err != nil {
			ctx.Resp.WriteHeader(nghttp.StatusBadRequest)
			ctx.WriteString(err.Error())
		} else {
			ctx.Resp.WriteHeader(nghttp.StatusAccepted)
		}
	case "/api/v1/cfg/save":
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		// errors := ngcmd.ValidateCfg(b)
		// if len(errors) > 0 {
		// 	ctx.Resp.WriteHeader(nghttp.StatusNotAcceptable)
		// 	ctx.WriteString(strings.Join(errors, "\n"))
		// 	return nghttp.RequestEnd
		// }
		os.WriteFile(*ngcmd.Configfile, b, fs.ModeCharDevice)
		ctx.Resp.WriteHeader(nghttp.StatusAccepted)
	case "/api/v1/cfg/validate":
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := io.ReadAll(ctx.Req.Body)
		errors := ngcmd.ValidateCfg(b)
		ctx.Resp.WriteHeader(nghttp.StatusAccepted)
		if len(errors) > 0 {
			ctx.WriteString(strings.Join(errors, "\n"))
		} else {
			ctx.WriteString("ok")
		}
	case "/api/v1/cfg/get":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		b, _ := os.ReadFile(*ngcmd.Configfile)
		ctx.Resp.Write(b)
	case "/api/v1/cfg/getcur":
		ctx.Resp.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Write(curcfg)

	case "/api/v1/cfg/schema":
		ctx.Resp.Header().Set("Content-Type", "text/json; charset=utf-8")
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		if cachedSchema == nil {
			cachedSchema = GenerateJsonSchema()
		}
		ctx.Resp.Write(cachedSchema)
	case "/api/v1/call":
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		ctx.Resp.Header().Set("Cache-Control", "no-cache")
		ctx.Resp.Header().Set("Content-Type", "application/json; charset=utf-8")
		if ngcmd.CurSpace == nil {
			writeJSON(ctx, nghttp.StatusFailedDependency, apiCallResponse{
				Success: false,
				Error:   "runtime space is not available",
			})
			return nghttp.RequestEnd
		}
		decoder := json.NewDecoder(ctx.Req.Body)
		decoder.UseNumber()
		payload := map[string]interface{}{}
		if err := decoder.Decode(&payload); err != nil {
			writeJSON(ctx, nghttp.StatusBadRequest, apiCallResponse{
				Success: false,
				Error:   err.Error(),
			})
			return nghttp.RequestEnd
		}
		kind, _ := payload["kind"].(string)
		if strings.TrimSpace(kind) == "" {
			writeJSON(ctx, nghttp.StatusBadRequest, apiCallResponse{
				Success: false,
				Error:   "missing kind",
			})
			return nghttp.RequestEnd
		}
		specNode, err := buildArgNodeFromJSON(payload["spec"])
		if err != nil {
			writeJSON(ctx, nghttp.StatusBadRequest, apiCallResponse{
				Success: false,
				Error:   err.Error(),
			})
			return nghttp.RequestEnd
		}
		result, err := ngcmd.CurSpace.Call(kind, specNode)
		if err != nil {
			writeJSON(ctx, nghttp.StatusBadRequest, apiCallResponse{
				Success: false,
				Error:   err.Error(),
			})
			return nghttp.RequestEnd
		}
		response := apiCallResponse{
			Success: true,
			Result:  result,
		}
		if _, err := json.Marshal(response.Result); err != nil {
			response.Result = fmt.Sprint(result)
		}
		writeJSON(ctx, nghttp.StatusOK, response)
		return nghttp.RequestEnd

	case "/genhash":
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		b, _ := io.ReadAll(ctx.Req.Body)
		hashed, _ := bcrypt.GenerateFromPassword(b, 12)
		ctx.Resp.Write(hashed)
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
		if ctx.Req.Method != stdhttp.MethodPost {
			ctx.Resp.ErrorPage(nghttp.StatusMethodNotAllowed, "Method not allowed")
			return nghttp.RequestEnd
		}
		ctx.Resp.WriteHeader(nghttp.StatusAccepted)
		go func() {
			zlog.Warn().
				Str("type", "sys").
				Msg("the server is going down in 1 second")
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()

	case "/204":
		ctx.Resp.WriteHeader(204)

	case "/api/v1/space/map":
		space := u.getSpace()
		if space == nil {
			ng.WriteJSON(ctx.ResponseWriter(), 424, map[string]string{"error": "space not available"})
			return nghttp.RequestEnd
		}
		type nodeInfo struct {
			Name     string `json:"name"`
			Kind     string `json:"kind"`
			HasAdmin bool   `json:"hasAdmin"`
		}
		var nodes []nodeInfo
		for name, svc := range space.Services {
			_, hasAdmin := svc.(ng.AdminProvider)
			nodes = append(nodes, nodeInfo{
				Name:     name,
				Kind:     space.ServiceKinds[name],
				HasAdmin: hasAdmin,
			})
		}
		result := map[string]any{
			"nodes": nodes,
			"edges": space.Edges,
		}
		ng.WriteJSON(ctx.ResponseWriter(), 200, result)

	case "/api/v1/admin/modules":
		space := u.getSpace()
		if space == nil {
			ng.WriteJSON(ctx.ResponseWriter(), 424, map[string]string{"error": "space not available"})
			return nghttp.RequestEnd
		}
		type moduleInfo struct {
			Name string       `json:"name"`
			Kind string       `json:"kind"`
			Meta ng.AdminMeta `json:"meta"`
		}
		var modules []moduleInfo
		for name, svc := range space.Services {
			if provider, ok := svc.(ng.AdminProvider); ok {
				modules = append(modules, moduleInfo{
					Name: name,
					Kind: space.ServiceKinds[name],
					Meta: provider.AdminMeta(),
				})
			}
		}
		ng.WriteJSON(ctx.ResponseWriter(), 200, modules)

	default:
		if strings.HasPrefix(ctx.Req.URL.Path, "/debug/pprof") {
			stdhttp.DefaultServeMux.ServeHTTP(ctx.Resp, ctx.Req)
		} else {
			stdhttp.ServeFileFS(ctx.Resp, ctx.Req, index, "html/dist"+ctx.Req.URL.Path)
		}
	}
	return nghttp.RequestEnd
}
func (u *UI) getSpace() *ng.Space {
	if ngcmd.CurSpace != nil {
		return ngcmd.CurSpace
	}
	return nil
}

func (u *UI) handleInstanceRoute(ctx *nghttp.HttpCtx, name string, subPath string) bool {
	space := u.getSpace()
	if space == nil {
		return false
	}
	svc, ok := space.Services[name]
	if !ok {
		return false
	}
	provider, ok := svc.(ng.AdminProvider)
	if !ok {
		return false
	}
	meta := provider.AdminMeta()
	for _, route := range meta.Routes {
		if route.Path == subPath && route.Method == ctx.Req.Method {
			route.Handler(ctx)
			return true
		}
	}
	return false
}

func (u *UI) handleInstanceDetail(ctx *nghttp.HttpCtx, name string) {
	space := u.getSpace()
	if space == nil {
		ng.WriteJSON(ctx.ResponseWriter(), 424, map[string]string{"error": "space not available"})
		return
	}
	svc, ok := space.Services[name]
	if !ok {
		ng.WriteJSON(ctx.ResponseWriter(), 404, map[string]string{"error": "instance not found"})
		return
	}

	// Collect edges: who this instance depends on, and who depends on it
	var dependsOn []string
	var dependedBy []string
	for _, e := range space.Edges {
		if e.From == name {
			dependsOn = append(dependsOn, e.To)
		}
		if e.To == name {
			dependedBy = append(dependedBy, e.From)
		}
	}

	result := map[string]any{
		"name":       name,
		"kind":       space.ServiceKinds[name],
		"dependsOn":  dependsOn,
		"dependedBy": dependedBy,
	}
	if provider, ok := svc.(ng.AdminProvider); ok {
		result["admin"] = provider.AdminMeta()
	}
	ng.WriteJSON(ctx.ResponseWriter(), 200, result)
}

func (*UI) HandleHTTPInternal(ctx *nghttp.HttpCtx) nghttp.Ret {
	return nghttp.RequestEnd
}

func (*UI) PathsInternal() []*regexp2.Regexp {
	return nil
}

var curcfg []byte

var Sselogger = NewTextStreamLogger()

const (
	csrfCookieName = "ngcsrf"
	csrfHeaderName = "X-CSRF-Token"
)

const csrfTokenSize = 32

func ensureCSRFCookie(ctx *nghttp.HttpCtx) string {
	if c, err := ctx.Req.Cookie(csrfCookieName); err == nil && isValidCSRFToken(c.Value) {
		return c.Value
	}
	return issueCSRFCookie(ctx)
}

func requireCSRF(ctx *nghttp.HttpCtx) bool {
	cookie, err := ctx.Req.Cookie(csrfCookieName)
	if err != nil || !isValidCSRFToken(cookie.Value) {
		issueCSRFCookie(ctx)
		ctx.Resp.WriteHeader(nghttp.StatusForbidden)
		ctx.WriteString("CSRF token missing or invalid")
		return false
	}

	header := ctx.Req.Header.Get(csrfHeaderName)
	if !isValidCSRFToken(header) {
		ctx.Resp.WriteHeader(nghttp.StatusForbidden)
		ctx.WriteString("CSRF token missing or invalid")
		return false
	}

	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		issueCSRFCookie(ctx)
		ctx.Resp.WriteHeader(nghttp.StatusForbidden)
		ctx.WriteString("CSRF token mismatch")
		return false
	}

	return true
}

func issueCSRFCookie(ctx *nghttp.HttpCtx) string {
	token := newCSRFToken()
	ctx.SetCookie(&stdhttp.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: stdhttp.SameSiteStrictMode,
		Secure:   ctx.Req.TLS != nil,
	})
	return token
}

func newCSRFToken() string {
	b := make([]byte, csrfTokenSize)
	if _, err := rand.Read(b); err != nil {
		panic(errors.New("failed to generate random csrf cookie"))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func isValidCSRFToken(token string) bool {
	if token == "" {
		return false
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return false
	}
	return true
}

func isSafeHTTPMethod(method string) bool {
	switch method {
	case stdhttp.MethodGet, stdhttp.MethodHead, stdhttp.MethodOptions:
		return true
	default:
		return false
	}
}

func Reload() error {

	ReloadTime = time.Now()
	ReloadCount++

	r, err := os.ReadFile(*ngcmd.Configfile)

	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	if err := ngcmd.LoadCfg(r, true); err != nil {
		return err
	}

	return nil
}

func buildArgNodeFromJSON(v interface{}) (*ng.ArgNode, error) {
	if v == nil {
		return &ng.ArgNode{Type: "null", Value: nil}, nil
	}
	normalized, err := normalizeJSONValue(v)
	if err != nil {
		return nil, err
	}
	node := &ng.ArgNode{}
	if err := node.FromAny(normalized); err != nil {
		return nil, err
	}
	return node, nil
}

func normalizeJSONValue(v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case json.Number:
		if strings.ContainsAny(val.String(), ".eE") {
			f, err := val.Float64()
			if err != nil {
				return nil, err
			}
			return f, nil
		}
		if i, err := val.Int64(); err == nil {
			return int(i), nil
		}
		f, err := val.Float64()
		if err != nil {
			return nil, err
		}
		return f, nil
	case map[string]interface{}:
		res := make(map[string]interface{}, len(val))
		for k, v := range val {
			norm, err := normalizeJSONValue(v)
			if err != nil {
				return nil, err
			}
			res[k] = norm
		}
		return res, nil
	case []interface{}:
		res := make([]interface{}, len(val))
		for i, v := range val {
			norm, err := normalizeJSONValue(v)
			if err != nil {
				return nil, err
			}
			res[i] = norm
		}
		return res, nil
	default:
		return v, nil
	}
}

func writeJSON(ctx *nghttp.HttpCtx, status int, payload any) {
	ctx.Resp.WriteHeader(status)
	enc := json.NewEncoder(ctx.Resp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		zlog.Error().Err(err).Msg("failed to encode json response")
	}
}

var _ nghttp.Service = (*UI)(nil)
