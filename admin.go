package ng

import (
	"encoding/json"
	stdhttp "net/http"
)

// AdminContext is the interface that admin route handlers receive.
// *nghttp.HttpCtx satisfies this via structural typing — ng and nghttp
// never import each other for this purpose.
type AdminContext interface {
	ResponseWriter() stdhttp.ResponseWriter
	Request() *stdhttp.Request
}

// WriteJSON is a package-level convenience function for admin handlers.
func WriteJSON(w stdhttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type AdminHandler func(AdminContext)

// AdminProvider is implemented by service instances that want to
// contribute pages to the admin UI. Discovered via type assertion
// after Space.Apply().
type AdminProvider interface {
	AdminMeta() AdminMeta
}

type AdminMeta struct {
	Title    string       `json:"title"`
	Category string       `json:"category"`
	Icon     string       `json:"icon,omitempty"`
	Priority int          `json:"priority,omitempty"`
	Root     Widget       `json:"root"`
	Routes   []AdminRoute `json:"-"`
}

type AdminRoute struct {
	Method  string
	Path    string
	Desc    string
	Handler AdminHandler
}
