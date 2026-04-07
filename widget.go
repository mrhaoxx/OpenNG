package ng

import "encoding/json"

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

type Stream struct {
	Source     string `json:"source"`
	Format     string `json:"format,omitempty"`
	MaxLines   int    `json:"maxLines,omitempty"`
	AutoScroll bool   `json:"autoscroll,omitempty"`
	Filterable bool   `json:"filterable,omitempty"`
}

func (Stream) WidgetType() string { return "stream" }

type Code struct {
	Source         string `json:"source"`
	Language       string `json:"language,omitempty"`
	ReadOnly       bool   `json:"readonly,omitempty"`
	SubmitEndpoint string `json:"submitEndpoint,omitempty"`
	SubmitMethod   string `json:"submitMethod,omitempty"`
}

func (Code) WidgetType() string { return "code" }

type KV struct {
	Source string     `json:"source"`
	Fields []FieldDef `json:"fields"`
	Poll   string     `json:"poll,omitempty"`
}

func (KV) WidgetType() string { return "kv" }

type Form struct {
	Fields         []FieldDef `json:"fields"`
	SubmitEndpoint string     `json:"submitEndpoint"`
	SubmitMethod   string     `json:"submitMethod,omitempty"`
	ResetOnSubmit  bool       `json:"resetOnSubmit,omitempty"`
}

func (Form) WidgetType() string { return "form" }

type TextWidget struct {
	Content string `json:"content"`
	Variant string `json:"variant,omitempty"`
}

func (TextWidget) WidgetType() string { return "text" }

// --- Layout helpers ---

type columnsLayout struct{ Gap string `json:"gap,omitempty"` }

func (columnsLayout) WidgetType() string { return "columns" }

type columnLayout struct{ Span int `json:"span"` }

func (columnLayout) WidgetType() string { return "column" }

type cardLayout struct{ Title string `json:"title"` }

func (cardLayout) WidgetType() string { return "card" }

type tabsLayout struct{}

func (tabsLayout) WidgetType() string { return "tabs" }

type tabLayout struct {
	Label string `json:"label"`
	Icon  string `json:"icon,omitempty"`
}

func (tabLayout) WidgetType() string { return "tab" }

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

func Tabs(children ...Widget) Widget {
	return Widget{Content: tabsLayout{}, Children: children}
}

func Tab(label string, children ...Widget) Widget {
	return Widget{Content: tabLayout{Label: label}, Children: children}
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

type FieldDef struct {
	Field       string      `json:"field"`
	Label       string      `json:"label"`
	Type        string      `json:"type"`
	Required    bool        `json:"required,omitempty"`
	Default     any         `json:"default,omitempty"`
	Options     []OptionDef `json:"options,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Validation  string      `json:"validation,omitempty"`
	HelpText    string      `json:"helpText,omitempty"`
}

type ActionDef struct {
	Label    string `json:"label"`
	Icon     string `json:"icon,omitempty"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Variant  string `json:"variant,omitempty"`
	Confirm  string `json:"confirm,omitempty"`
}

type OptionDef struct {
	Label string `json:"label"`
	Value any    `json:"value"`
}
