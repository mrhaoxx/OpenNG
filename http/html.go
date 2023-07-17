package http

import (
	_ "embed"
	"html/template"
	"strconv"
)

var errorpage_template *template.Template = template.Must(template.New("errorpage").Parse(errorpage_rawhtml))
var redirecting_template *template.Template = template.Must(template.New("redirecting").Parse(redirecting_rawhtml))
var info_template *template.Template = template.Must(template.New("info").Parse(info_rawhtml))
var confirm_template = template.Must(template.New("confirm").Parse(confirm_rawhtml))

//go:embed html/error.html
var errorpage_rawhtml string

//go:embed html/redirecting.html
var redirecting_rawhtml string

//go:embed html/info.html
var info_rawhtml string

//go:embed html/confirm.html
var confirm_rawhtml string

func (ctx *HttpCtx) ErrorPage(code int, err string) {
	ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
	ctx.Resp.WriteHeader(code)
	errorpage_template.Execute(ctx.Resp, err)
}

func (ctx *HttpCtx) InfoPage(code int, info string) {
	ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
	ctx.Resp.WriteHeader(code)
	info_template.Execute(ctx.Resp, info)
}

// using http header: Refresh
func (ctx *HttpCtx) RefreshRedirectPage(code int, url string, msg string, time int) {
	ctx.Resp.Header().Set("Refresh", strconv.Itoa(time)+";url="+url)
	ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
	ctx.Resp.WriteHeader(code)
	redirecting_template.Execute(ctx.Resp, struct {
		URL string
		MSG string
	}{URL: url, MSG: msg})
}

func (ctx *HttpCtx) ConfrimPage(code int, url string, msg string) {
	ctx.Resp.Header().Add("Content-Type", "text/html; charset=utf-8")
	ctx.Resp.WriteHeader(code)
	confirm_template.Execute(ctx.Resp, struct {
		URL string
		MSG string
	}{URL: url, MSG: msg})
}
