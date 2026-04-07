package ng

import (
	"encoding/json"
	stdhttp "net/http"
)

// AdminContext is the interface that admin route handlers receive.
// *nghttp.HttpCtx satisfies this via structural typing.
type AdminContext interface {
	ResponseWriter() stdhttp.ResponseWriter
	Request() *stdhttp.Request
}

func WriteJSON(w stdhttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type AdminHandler func(AdminContext)

// AdminProvider is optionally implemented by service instances
// to provide custom monitoring widgets and API routes.
type AdminProvider interface {
	AdminMeta() AdminMeta
}

type AdminMeta struct {
	Root   Widget       `json:"root"`
	Routes []AdminRoute `json:"-"`
}

type AdminRoute struct {
	Method  string
	Path    string
	Handler AdminHandler
}
