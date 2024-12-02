package ui

import (
	_ "embed"
	"net/http"
)

//go:embed NetGATE.svg
var logo_svg string

func WriteLogo(resp http.ResponseWriter) {
	resp.Header().Set("Content-Type", "image/svg+xml")
	resp.Header().Set("Cache-Control", "max-age=2592000")
	resp.Write([]byte(logo_svg))
}
