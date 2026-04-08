// Package widget defines the admin UI widget type system and provider interface.
// This package has no dependencies on any module, so it can be imported by all services.
package widget

import (
	"encoding/json"
	stdhttp "net/http"
)

// AdminContext is the interface that admin route handlers receive.
type AdminContext interface {
	ResponseWriter() stdhttp.ResponseWriter
	Request() *stdhttp.Request
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w stdhttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// AdminHandler is a function that handles an admin API request.
type AdminHandler func(AdminContext)

// AdminProvider is optionally implemented by service instances
// to provide custom monitoring widgets and API routes.
type AdminProvider interface {
	AdminMeta() AdminMeta
}

// AdminMeta describes a service's admin UI and API routes.
type AdminMeta struct {
	Root   Widget       `json:"root"`
	Routes []AdminRoute `json:"-"`
}

// AdminRoute is a custom API route exposed by a service.
type AdminRoute struct {
	Method  string
	Path    string
	Handler AdminHandler
}

// WidgetContent is implemented by each widget type.
type WidgetContent interface {
	WidgetType() string
}

// Widget is a node in the admin UI tree.
type Widget struct {
	Content  WidgetContent `json:"-"`
	Children []Widget      `json:"children,omitempty"`
}

func (w Widget) MarshalJSON() ([]byte, error) {
	if w.Content == nil {
		return json.Marshal(struct {
			Type     string   `json:"type"`
			Children []Widget `json:"children,omitempty"`
		}{"empty", w.Children})
	}
	return json.Marshal(struct {
		Type     string   `json:"type"`
		Props    any      `json:"props"`
		Children []Widget `json:"children,omitempty"`
	}{w.Content.WidgetType(), w.Content, w.Children})
}

// --- Data widgets ---

type Table struct {
	Source     string      `json:"source"`
	Columns    []ColumnDef `json:"columns"`
	Poll       string      `json:"poll,omitempty"`
	Searchable bool        `json:"searchable,omitempty"`
	Sortable   bool        `json:"sortable,omitempty"`
	Paginated  bool        `json:"paginated,omitempty"`
	PageSize   int         `json:"pageSize,omitempty"`
	RowKey     string      `json:"rowKey,omitempty"`
}

func (Table) WidgetType() string { return "table" }

type Stat struct {
	Label  string `json:"label"`
	Source string `json:"source"`
	Field  string `json:"field,omitempty"`
	Unit   string `json:"unit,omitempty"`
	Icon   string `json:"icon,omitempty"`
	Poll   string `json:"poll,omitempty"`
}

func (Stat) WidgetType() string { return "stat" }

type Action struct {
	Label    string `json:"label"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Icon     string `json:"icon,omitempty"`
	Variant  string `json:"variant,omitempty"`
	Confirm  string `json:"confirm,omitempty"`
}

func (Action) WidgetType() string { return "action" }

// --- Layout helpers ---

type columnsLayout struct{ Gap string `json:"gap,omitempty"` }

func (columnsLayout) WidgetType() string { return "columns" }

type columnLayout struct{ Span int `json:"span"` }

func (columnLayout) WidgetType() string { return "column" }

type cardLayout struct{ Title string `json:"title"` }

func (cardLayout) WidgetType() string { return "card" }

type rowLayout struct{ Gap string `json:"gap,omitempty"` }

func (rowLayout) WidgetType() string { return "row" }

func Columns(children ...Widget) Widget {
	return Widget{Content: columnsLayout{}, Children: children}
}

func Column(span int, children ...Widget) Widget {
	return Widget{Content: columnLayout{Span: span}, Children: children}
}

func Card(title string, children ...Widget) Widget {
	return Widget{Content: cardLayout{Title: title}, Children: children}
}

func Row(children ...Widget) Widget {
	return Widget{Content: rowLayout{}, Children: children}
}

// --- Sub-structures ---

type ColumnDef struct {
	Field    string            `json:"field"`
	Label    string            `json:"label"`
	Type     string            `json:"type"`
	Sortable bool              `json:"sortable,omitempty"`
	Width    string            `json:"width,omitempty"`
	ColorMap map[string]string `json:"colorMap,omitempty"`
	Actions  []ActionDef       `json:"actions,omitempty"`
}

type ActionDef struct {
	Label    string `json:"label"`
	Icon     string `json:"icon,omitempty"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Variant  string `json:"variant,omitempty"`
	Confirm  string `json:"confirm,omitempty"`
}
