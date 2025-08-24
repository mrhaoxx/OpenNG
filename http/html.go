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
	errorpage_template.Execute(rw, struct {
		MSG string
		RID string
		RIP string
		// CID  string
		CODE string
		UTC  string
		// ELA  string
		TAR string
	}{
		MSG:  err,
		CODE: strconv.Itoa(code),
		RID:  rw.ctx.Id,
		RIP:  rw.ctx.RemoteIP,
		// CID:  strconv.FormatUint(rw.ctx.conn.Id, 10),
		UTC: rw.ctx.starttime.UTC().Format("2006\u201101\u201102\u00A015:04:05\u00A0UTC"),
		// ELA: time.Since(rw.ctx.starttime).String(),
		TAR: rw.ctx.Req.Host + rw.ctx.Req.RequestURI,
	})
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
		URL  string
		MSG  string
		TIME int
	}{URL: url, MSG: msg, TIME: time})
}

func (rw *NgResponseWriter) ConfrimPage(code int, url string, msg string) {
	rw.Header().Add("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(code)
	confirm_template.Execute(rw, struct {
		URL string
		MSG string
	}{URL: url, MSG: msg})
}
