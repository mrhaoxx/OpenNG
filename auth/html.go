package auth

import (
	"embed"
	"html/template"
)

//go:embed html
var raw_htmls embed.FS

var userlogin *template.Template
var permission_denied *template.Template

func init() {
	var err error
	userlogin, err = template.ParseFS(raw_htmls, "html/login.html")
	if err != nil {
		panic(err)
	}
	permission_denied, err = template.ParseFS(raw_htmls, "html/login_layout.html", "html/login_permission_denied.html")
	if err != nil {
		panic(err)
	}
}
