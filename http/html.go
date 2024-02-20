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

func (rw *NgResponseWriter) ErrorPage(code int, err string) {
	rw.Header().Add("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	errorpage_template.Execute(rw, err)
}

func (rw *NgResponseWriter) InfoPage(code int, info string) {
	rw.Header().Add("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	info_template.Execute(rw, info)
}

// using http header: Refresh
func (rw *NgResponseWriter) RefreshRedirectPage(code int, url string, msg string, time int) {
	rw.Header().Set("Refresh", strconv.Itoa(time)+";url="+url)
	rw.Header().Add("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	redirecting_template.Execute(rw, struct {
		URL string
		MSG string
	}{URL: url, MSG: msg})
}

func (rw *NgResponseWriter) ConfrimPage(code int, url string, msg string) {
	rw.Header().Add("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	confirm_template.Execute(rw, struct {
		URL string
		MSG string
	}{URL: url, MSG: msg})
}
