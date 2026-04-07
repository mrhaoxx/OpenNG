# OpenNG Architecture Redesign

Date: 2026-04-07
Status: Draft

## Overview

A breaking redesign of the OpenNG architecture covering four areas:

1. **Directory restructure** — `pkg/` for pure libraries, `modules/` for service packages with Kind registration
2. **Module system** — replace `init()` global state with explicit Kind registration and `Space` constructed from Kind lists
3. **Admin extensibility** — services declare admin UI via `ng.AdminProvider` interface and a composable widget tree
4. **mTLS decoupling** — remove client cert concerns from auth backend interface; use interface segregation

No backward compatibility is maintained for Go import paths or YAML configuration.

---

## 1. Directory Structure

### Problem

`pkg/` and `modules/` mirror each other 1:1. `modules/X` is a thin `init()` wrapper around `pkg/X`. Two parallel directory trees for one package per domain. The `pkg/` packages are not reusable outside this project.

### Design

Split into two directories with a clear rule:

- **`pkg/`** — pure library code. No Kind registration. No `module.go`. Importable by anyone.
- **`modules/`** — service packages that export Kinds. Each has a `module.go` with an exported Kind slice.

```
github.com/mrhaoxx/OpenNG/
├── netgate.go               # ng root: ArgNode, Assert, Kind, Widget, AdminProvider
├── space.go                 # Space, Apply, Deptr, Call
├── module.go                # Kind type, Reloadable interface, admin types
│
├── pkg/                     # pure libraries (no Kind registration)
│   ├── groupexp/            # grouped regexp
│   ├── lookup/              # DNS lookup
│   ├── ngnet/               # network utilities (URL, RwConn, addr)
│   └── log/                 # structured logging
│
├── modules/                 # service packages (each exports Kinds)
│   ├── nghttp/              # HTTP: HttpCtx, Midware, proxy, CGI, ...
│   ├── ngtcp/               # TCP: Controller, Conn, detect, proxy
│   ├── ngtls/               # TLS: TlsMgr, certificate, handshake
│   ├── ngssh/               # SSH: Midware, proxy
│   ├── ngdns/               # DNS: server
│   ├── auth/                # authentication: backends, policybase
│   ├── admin/               # admin UI (SPA, discovers AdminProvider)
│   ├── expr/                # expression evaluation
│   ├── misc/                # misc services
│   └── tunnels/             # tunnel implementations
│       ├── tunnel.go        # Overlay interface
│       ├── http/
│       ├── trojan/
│       └── wireguard/
│
└── cmd/
    ├── config.go
    └── netgate/
        └── main.go          # explicit module loading
```

### Naming rules

- Packages that shadow stdlib keep the `ng` prefix: `nghttp`, `ngtcp`, `ngtls`, `ngnet`, `ngssh`, `ngdns`
- Packages that don't shadow stdlib use plain names: `auth`, `admin`, `expr`, `misc`
- `modules/admin` package declaration changes from `ui` to `admin`

---

## 2. Module System

### Problem

The current system uses `init()` + `ng.Register()` into package-level global maps. This is invisible, untestable, order-dependent, and makes modules impossible to discover at runtime.

### Design

#### 2.1 Kind as the registration unit

No `Module` grouping type. Kind is flat and self-contained:

```go
// Root package ng

type Kind struct {
    Name   string   // "tls", "http::midware", "auth::backend::file"
    Assert Assert   // argument schema (optional if using From())
    Return Assert   // return type schema (optional if using From())
    New    Constructor
}

type Constructor func(*ArgNode) (any, error)
```

Each service package exports its Kinds:

```go
// modules/ngtls/module.go
package ngtls

var Kinds = []ng.Kind{
    {Name: "tls", Assert: tlsAssert, Return: ng.Assert{Type: "ptr"}, New: newTlsMgr},
    {Name: "tls::reload", Assert: reloadAssert, New: newReload},
}
```

#### 2.2 Explicit loading — no init()

```go
// cmd/netgate/main.go
package main

import (
    "github.com/mrhaoxx/OpenNG/modules/ngtls"
    "github.com/mrhaoxx/OpenNG/modules/ngtcp"
    "github.com/mrhaoxx/OpenNG/modules/nghttp"
    "github.com/mrhaoxx/OpenNG/modules/ngssh"
    "github.com/mrhaoxx/OpenNG/modules/ngdns"
    "github.com/mrhaoxx/OpenNG/modules/auth"
    "github.com/mrhaoxx/OpenNG/modules/admin"
    "github.com/mrhaoxx/OpenNG/modules/expr"
    "github.com/mrhaoxx/OpenNG/modules/misc"
    tunnelshttp "github.com/mrhaoxx/OpenNG/modules/tunnels/http"
    // ...
)

func main() {
    ngcmd.Run(
        ngtls.Kinds,
        ngtcp.Kinds,
        nghttp.Kinds,
        ngssh.Kinds,
        ngdns.Kinds,
        auth.Kinds,
        admin.Kinds,
        expr.Kinds,
        misc.Kinds,
        tunnelshttp.Kinds,
        // ...
    )
}
```

#### 2.3 Space constructed from Kinds

No global registry. Space receives Kinds explicitly:

```go
func NewSpace(kindSets ...[]Kind) *Space {
    s := &Space{kinds: make(map[string]Kind), services: make(map[string]any)}
    for _, set := range kindSets {
        for _, k := range set {
            s.kinds[k.Name] = k
        }
    }
    return s
}
```

`ngcmd.Run` wraps this:

```go
func Run(kindSets ...[]ng.Kind) {
    space := ng.NewSpace(kindSets...)
    cfg := loadConfig()
    space.Apply(cfg)
    select {} // same as current — lifecycle management is out of scope
}
```

#### 2.4 Schema derivation from function signature (future)

`Kind.Assert` and `Kind.Return` can be omitted if the constructor is a typed Go function. The existing `RegisterFunc` reflection logic (already in `netgate.go`) can be adapted to derive schemas automatically:

```go
// Instead of manually constructing Assert:
{Name: "tls", Assert: tlsAssert, Return: retAssert, New: newTlsMgr}

// Schema derived from function signature:
ng.From(newTlsMgr)  // returns Kind with Name, Assert, Return, New all populated
```

Where `newTlsMgr` is `func(cfg TlsConfig) (*TlsMgr, error)`. This is a follow-up optimization, not a blocker for the initial restructure.

---

## 3. Admin Extensibility

### Problem

Admin hard-imports every module. Adding monitoring for a new module requires editing admin source code. The UI is multi-page server-rendered HTML.

### Design

#### 3.1 AdminProvider interface and types in root package

All admin types live in the root `ng` package. No separate `ngadmin` package.

```go
// Root package ng

// AdminContext is the interface admin route handlers receive.
// *nghttp.HttpCtx satisfies this through Go structural typing.
// nghttp does not need to import ng for this; ng does not import nghttp.
type AdminContext interface {
    http.ResponseWriter
    Request() *http.Request
}

// WriteJSON is a convenience function, not an interface method.
func WriteJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(v)
}

type AdminHandler func(AdminContext)

type AdminProvider interface {
    AdminMeta() AdminMeta
}

type AdminMeta struct {
    Name     string       // unique identifier: "tls", "auth"
    Title    string       // display name: "TLS Certificates"
    Category string       // nav group: "Security", "Network", "System"
    Icon     string       // icon identifier for frontend
    Priority int          // sort within category (lower = first)
    Root     Widget       // widget tree describing the UI
    Routes   []AdminRoute // API endpoints
}

type AdminRoute struct {
    Method  string        // "GET", "POST", "DELETE"
    Path    string        // "/api/v1/tls/certs"
    Desc    string        // human-readable description
    Handler AdminHandler
}
```

nghttp.HttpCtx satisfies `AdminContext` through structural typing — `ng` and `nghttp` never import each other for this. nghttp just needs these methods on HttpCtx:

```go
// In nghttp — HttpCtx already wraps http.ResponseWriter and has Request()
func (ctx *HttpCtx) Request() *http.Request { return ctx.Req }
// HttpCtx.Resp already implements http.ResponseWriter
```

Admin discovers providers at runtime via type assertion on `Space.Services`:

```go
// In admin module
for _, svc := range space.Services() {
    if p, ok := svc.(ng.AdminProvider); ok {
        mount(p)
    }
}
```

#### 3.2 Widget system — typed structs

Widget tree uses the `WidgetContent` interface for type safety. No `map[string]any` in module code.

```go
// Root package ng

type WidgetContent interface {
    WidgetType() string
}

type Widget struct {
    Content  WidgetContent `json:"-"`
    Children []Widget      `json:"children,omitempty"`
}

// JSON serialization: {type, props, children}
func (w Widget) MarshalJSON() ([]byte, error) {
    return json.Marshal(struct {
        Type     string      `json:"type"`
        Props    any         `json:"props"`
        Children []Widget    `json:"children,omitempty"`
    }{w.Content.WidgetType(), w.Content, w.Children})
}
```

#### 3.3 Concrete widget types

Each widget is a Go struct with proper types and json tags:

```go
// Data widgets

type Table struct {
    Source     string      `json:"source"`
    Columns   []ColumnDef `json:"columns"`
    Poll      string      `json:"poll,omitempty"`
    Searchable bool       `json:"searchable,omitempty"`
    Sortable   bool       `json:"sortable,omitempty"`
    Paginated  bool       `json:"paginated,omitempty"`
    PageSize   int        `json:"pageSize,omitempty"`
    RowKey     string     `json:"rowKey,omitempty"`
    Expandable bool       `json:"expandable,omitempty"`
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
    Variant  string `json:"variant,omitempty"`  // "primary", "danger", "default"
    Confirm  string `json:"confirm,omitempty"`
}
func (Action) WidgetType() string { return "action" }

type Stream struct {
    Source     string `json:"source"`
    Format    string `json:"format,omitempty"`
    MaxLines  int    `json:"maxLines,omitempty"`
    AutoScroll bool  `json:"autoscroll,omitempty"`
    Filterable bool  `json:"filterable,omitempty"`
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
    Layout         string     `json:"layout,omitempty"` // "vertical", "horizontal", "inline"
}
func (Form) WidgetType() string { return "form" }

type Text struct {
    Content string `json:"content"`
    Variant string `json:"variant,omitempty"` // "body", "caption", "heading"
}
func (Text) WidgetType() string { return "text" }

type Chart struct {
    Source    string   `json:"source"`
    ChartType string  `json:"chartType"` // "line", "bar", "area", "pie"
    Series   []string `json:"series,omitempty"`
    Poll     string   `json:"poll,omitempty"`
}
func (Chart) WidgetType() string { return "chart" }

type Detail struct {
    Source string     `json:"source"`
    Fields []FieldDef `json:"fields"`
}
func (Detail) WidgetType() string { return "detail" }

type Toggle struct {
    Source   string `json:"source"`
    Field    string `json:"field"`
    Endpoint string `json:"endpoint"`
    Label    string `json:"label"`
}
func (Toggle) WidgetType() string { return "toggle" }

// Layout types (used internally by layout helpers)

type columnsLayout struct{ Gap string `json:"gap,omitempty"` }
func (columnsLayout) WidgetType() string { return "columns" }

type columnLayout struct {
    Span     int    `json:"span"`
    MinWidth string `json:"minWidth,omitempty"`
}
func (columnLayout) WidgetType() string { return "column" }

type cardLayout struct {
    Title       string `json:"title"`
    Description string `json:"description,omitempty"`
    Collapsible bool   `json:"collapsible,omitempty"`
}
func (cardLayout) WidgetType() string { return "card" }

type tabsLayout struct{ DefaultTab string `json:"defaultTab,omitempty"` }
func (tabsLayout) WidgetType() string { return "tabs" }

type tabLayout struct {
    Label string `json:"label"`
    Icon  string `json:"icon,omitempty"`
    Key   string `json:"key,omitempty"`
}
func (tabLayout) WidgetType() string { return "tab" }

type rowLayout struct {
    Gap     string `json:"gap,omitempty"`
    Align   string `json:"align,omitempty"`
    Justify string `json:"justify,omitempty"`
}
func (rowLayout) WidgetType() string { return "row" }
```

#### 3.4 Layout helpers

Layout helpers are the only constructors. Data widgets use struct literals directly.

```go
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
```

#### 3.5 Sub-structures

```go
type ColumnDef struct {
    Field    string            `json:"field"`
    Label    string            `json:"label"`
    Type     string            `json:"type"`     // "string", "number", "datetime", "duration",
                                                  // "badge", "ip", "bool", "bytes", "link"
    Sortable bool              `json:"sortable,omitempty"`
    Width    string            `json:"width,omitempty"`
    ColorMap map[string]string `json:"colorMap,omitempty"`
    Actions  []ActionDef       `json:"actions,omitempty"`
}

type FieldDef struct {
    Field       string      `json:"field"`
    Label       string      `json:"label"`
    Type        string      `json:"type"` // "text", "number", "password", "textarea",
                                           // "select", "multiselect", "checkbox",
                                           // "file", "json", "duration", "readonly"
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
    Endpoint string `json:"endpoint"`    // supports {field} interpolation
    Method   string `json:"method"`
    Variant  string `json:"variant,omitempty"`
    Confirm  string `json:"confirm,omitempty"`
}

type OptionDef struct {
    Label string `json:"label"`
    Value any    `json:"value"`
}
```

#### 3.6 Implementation priority

First iteration widgets: `columns`, `column`, `card`, `table`, `stat`, `action`, `text`, `stream`, `kv`, `form`, `code`.

Add remaining types (`chart`, `detail`, `toggle`, `tabs`, `row`, etc.) as modules need them.

Frontend must render a styled fallback for unrecognized widget types (type name + raw props as JSON).

#### 3.7 Example: TLS module

```go
// modules/ngtls/admin.go

func (mgr *TlsMgr) AdminMeta() ng.AdminMeta {
    return ng.AdminMeta{
        Name:     "tls",
        Title:    "TLS Certificates",
        Category: "Security",
        Icon:     "shield-check",
        Priority: 10,
        Routes: []ng.AdminRoute{
            {Method: "GET",  Path: "/api/v1/tls/certs",  Handler: mgr.handleListCerts},
            {Method: "POST", Path: "/api/v1/tls/reload", Handler: mgr.handleReload},
        },
        Root: ng.Columns(
            ng.Column(8,
                ng.Card("Certificates",
                    ng.Widget{Content: ng.Table{
                        Source:     "/api/v1/tls/certs",
                        Poll:       "30s",
                        Searchable: true,
                        Columns: []ng.ColumnDef{
                            {Field: "domain",  Label: "Domain",  Type: "string"},
                            {Field: "issuer",  Label: "Issuer",  Type: "string"},
                            {Field: "expiry",  Label: "Expires", Type: "datetime"},
                            {Field: "status",  Label: "Status",  Type: "badge",
                             ColorMap: map[string]string{
                                "valid": "green", "expiring": "yellow", "expired": "red",
                             }},
                        },
                    }},
                ),
            ),
            ng.Column(4,
                ng.Widget{Content: ng.Stat{
                    Label: "Active Certificates", Source: "/api/v1/tls/certs", Icon: "certificate",
                }},
                ng.Widget{Content: ng.Action{
                    Label: "Reload All", Endpoint: "/api/v1/tls/reload",
                    Method: "POST", Variant: "primary", Confirm: "Reload all certificates?",
                }},
            ),
        ),
    }
}
```

#### 3.8 Frontend SPA

Replace the current multi-page webpack build with a single SPA:

- **Framework**: Preact
- **Widget renderer**: Recursive `renderWidget(widget)` with a component registry map. Unknown types render a styled fallback.
- **Navigation**: Auto-generated sidebar from module categories and priorities
- **Data layer**: Each data widget independently manages its own fetch/poll/stream lifecycle
- **Theming**: Existing Tailwind-based dark/light theme
- **Build output**: Single `index.html` with inlined JS/CSS, embedded via `embed.FS`
- **Routing**: Hash-based client-side routing (`#/tls`, `#/auth`)

#### 3.9 Data source conventions

- String `source` props: `"/api/v1/tls/certs"` → GET with no polling
- Polling: set `Poll` field on the widget struct
- Streaming: `Stream` widget type with SSE endpoint
- Path parameters: `"/api/v1/tls/certs/{id}"` — frontend substitutes from row context
- All admin API endpoints prefixed `/api/v1/`, namespaced by module

---

## 4. mTLS Decoupling

### Problem

`PolicyBackend` interface is contaminated with methods that don't belong on all backends:
- `CheckClientCert()` — LDAP returns `("", false)` unconditionally
- `AllowForwardProxy()` — LDAP returns `false` unconditionally

mTLS cannot be used without the auth module.

### Design

#### 4.1 Interface segregation on PolicyBackend

```go
// Core interface — all backends implement this
type PolicyBackend interface {
    CheckPassword(username, password string) bool
    ExistsUser(username string) bool
}

// Optional capability interfaces — backends implement if relevant
type SSHKeyChecker interface {
    CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) bool
}

type ForwardProxyAuthorizer interface {
    AllowForwardProxy(username string) bool
}
```

The backend group discovery loop uses type assertions:

```go
func (b backendGroup) CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) (bool, int) {
    for i, backend := range b {
        if checker, ok := backend.(SSHKeyChecker); ok {
            if checker.CheckSSHKey(ctx, key) { return true, i }
        }
    }
    return false, -1
}
```

#### 4.2 Cert mapping as policy concern

Cert-to-user mapping lives in `policyBaseAuth`, not in backends:

```go
type policyBaseAuth struct {
    // ... existing fields
    certMappings      map[string]string // SHA256 fingerprint → username
    forwardProxyUsers map[string]bool   // users allowed forward proxy
}
```

Configuration:

```yaml
auth::policyd:
  CertMappings:
    - Fingerprint: "ab12cd..."
      Username: "alice"
  ForwardProxyUsers:
    - alice
    - bob
  Policies:
    # ... existing
```

#### 4.3 Auth flow

```
Request arrives
  → preparetls() populates r.TLS (existing)
  → HandleAuth() checks cookie session (existing)
  → If no session && r.TLS.PeerCertificates present:
      compute SHA256 fingerprint of PeerCertificates[0]
      look up in policyBaseAuth.certMappings
      if found → create session for that user
  → Continue with policy evaluation (existing)
```

#### 4.4 TLS and HTTP layers

Unchanged. TLS layer validates cert chain via `VerifyClientCertIfGiven` + client CA pool. HTTP layer populates `r.TLS` via `preparetls()`. Auth reads from `r.TLS.PeerCertificates`.

For mTLS without auth (just restrict connections to valid client certs), the TLS layer handles it alone.

---

## Execution Order

1. **Directory restructure + module system** (Section 1 + 2) — move files, replace init() with exported Kinds, update Space. Each dependency layer is one commit, bottom-up:
   - Foundation: `pkg/groupexp`, `pkg/log`, `pkg/lookup`, `pkg/ngnet`
   - Layer 1: `modules/ngdns`, `modules/ngtcp`
   - Layer 2: `modules/nghttp`, `modules/ngtls`, `modules/ngssh`, `modules/expr`
   - Layer 3: `modules/auth`, `modules/misc`, `modules/tunnels`
   - Entry point: update `cmd/netgate/main.go` to explicit loading
2. **mTLS decoupling** (Section 4) — clean up PolicyBackend, move cert mapping
3. **Admin extensibility** (Section 3) — add types to root package, implement AdminProvider in modules, build SPA

---

## Summary

| Area | Before | After |
|---|---|---|
| Directory | `pkg/` + `modules/` mirrored | `pkg/` = libraries, `modules/` = services with Kinds |
| Registration | `init()` + global `ng.Register()` | Exported `Kinds` var, `NewSpace(kindSets...)` |
| Module loading | Blank imports, implicit | Explicit list in `main()` |
| Lifecycle | None | None (out of scope, same as current) |
| Admin coupling | Hard imports of every module | `AdminProvider` interface, runtime discovery |
| Admin UI | Multi-page server-rendered HTML | Preact SPA, widget tree from `/api/v1/admin/modules` |
| Widget API | N/A | `WidgetContent` interface + typed structs + layout helpers |
| AdminContext | N/A | `http.ResponseWriter` + `Request()`, structural typing |
| PolicyBackend | 5 methods, all required | 2 core + optional `SSHKeyChecker`, `ForwardProxyAuthorizer` |
| mTLS identity | Embedded in backend interface | Policy-level cert mapping in `policyBaseAuth` |
| Root package | `Register()`, `ArgNode`, `Assert`, `Space` | + `Kind`, `Constructor`, `Widget`, `AdminProvider`, `AdminContext` |
