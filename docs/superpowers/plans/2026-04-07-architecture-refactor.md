# Architecture Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge pkg/ and modules/ into unified packages, decouple admin from hard-coded module imports, decouple mTLS from auth backend interface.

**Architecture:** Three independent changes. (1) Move each `pkg/X` implementation into the corresponding `modules/X` package, updating all import paths. (2) Add `AdminProvider` interface + Widget type system to root `ng` package; refactor admin to discover providers at runtime. (3) Clean up `PolicyBackend` interface using interface segregation; move cert mapping to policy layer.

**Tech Stack:** Go, Preact (frontend SPA — separate effort, not in this plan)

---

## Part 1: Merge `pkg/` into `modules/`

Each task moves one `pkg/` package into its corresponding `modules/` package (or creates a new one), updates all import paths project-wide, and verifies the build compiles. Order follows the dependency graph bottom-up.

### Task 1: Move `pkg/groupexp` → `modules/groupexp`

**Files:**
- Move: `pkg/groupexp/groupexp.go` → `modules/groupexp/groupexp.go`
- Modify: every file that imports `github.com/mrhaoxx/OpenNG/pkg/groupexp`

- [ ] **Step 1: Create destination and move file**

```bash
mkdir -p modules/groupexp
mv pkg/groupexp/groupexp.go modules/groupexp/groupexp.go
```

- [ ] **Step 2: Update all import paths**

Find and replace `"github.com/mrhaoxx/OpenNG/pkg/groupexp"` with `"github.com/mrhaoxx/OpenNG/modules/groupexp"` in all `.go` files. Files to update (grep the codebase to confirm exact list):
- `netgate.go`
- `pkg/nghttp/http.go` (and other nghttp files using groupexp)
- `pkg/ngtls/certificate.go`
- `pkg/ngssh/midware.go`
- `pkg/auth/policybase.go`
- `pkg/expr/*.go`
- `pkg/misc/*.go`
- `modules/admin/ui.go`
- `modules/http/app.go`

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

Expected: compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move pkg/groupexp to modules/groupexp"
```

### Task 2: Move `pkg/log` → `modules/log`

**Files:**
- Move: `pkg/log/log.go` → `modules/log/log.go`
- Modify: `modules/log/app.go` (update import, fix package name conflict if any)
- Modify: every file importing `github.com/mrhaoxx/OpenNG/pkg/log`

- [ ] **Step 1: Move file**

`modules/log/` already exists with `app.go`. Move `pkg/log/log.go` there. Both are `package log` so no conflict.

```bash
mv pkg/log/log.go modules/log/log.go
```

- [ ] **Step 2: Update all import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/log"` with `"github.com/mrhaoxx/OpenNG/modules/log"` in all `.go` files. Key files:
- `modules/admin/app.go`
- `modules/log/app.go` (self-import)

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move pkg/log into modules/log"
```

### Task 3: Move `pkg/lookup` → `modules/lookup`

**Files:**
- Move: `pkg/lookup/lookup.go`, `pkg/lookup/lookup_test.go` → `modules/lookup/`
- Modify: importers (`pkg/nghttp/`, `pkg/ngtls/`, `pkg/auth/`)

- [ ] **Step 1: Move files**

```bash
mkdir -p modules/lookup
mv pkg/lookup/*.go modules/lookup/
```

- [ ] **Step 2: Update import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/lookup"` with `"github.com/mrhaoxx/OpenNG/modules/lookup"`.

- [ ] **Step 3: Build and run tests**

```bash
go build ./...
go test ./modules/lookup/...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move pkg/lookup to modules/lookup"
```

### Task 4: Move `pkg/ngnet` → `modules/ngnet`

**Files:**
- Move: all files in `pkg/ngnet/` → `modules/ngnet/`
- Modify: heavy usage across `netgate.go`, `instance.go`, `pkg/nghttp/`, `pkg/ngtcp/`, `pkg/ngtls/`, `modules/http/`, `modules/net/`, `modules/tunnels/`

- [ ] **Step 1: Move files**

```bash
mkdir -p modules/ngnet
mv pkg/ngnet/*.go modules/ngnet/
```

- [ ] **Step 2: Update all import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/ngnet"` with `"github.com/mrhaoxx/OpenNG/modules/ngnet"`. This is one of the most widely imported packages — grep carefully:

```bash
grep -r '"github.com/mrhaoxx/OpenNG/pkg/ngnet"' --include='*.go' -l
```

Update every file in the list.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move pkg/ngnet to modules/ngnet"
```

### Task 5: Move `pkg/ngdns` → `modules/ngdns` (merge with `modules/dns`)

**Files:**
- Move: `pkg/ngdns/server.go`, `pkg/ngdns/utils.go` → `modules/dns/`
- Modify: `modules/dns/app.go` (update imports, both become `package dns`)
- Note: `pkg/ngdns` is package `ngdns`, `modules/dns` is package `dns`. Decide package name. Keep `dns` since it's simpler. Rename package declaration in moved files.

- [ ] **Step 1: Move files and update package declaration**

```bash
mv pkg/ngdns/server.go modules/dns/server.go
mv pkg/ngdns/utils.go modules/dns/utils.go
```

Edit `modules/dns/server.go` and `modules/dns/utils.go`: change `package ngdns` to `package dns`.

- [ ] **Step 2: Update all import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/ngdns"` with `"github.com/mrhaoxx/OpenNG/modules/dns"`. Update import aliases — files that used `ngdns "..."` now need `ngdns "github.com/mrhaoxx/OpenNG/modules/dns"` or adjust to use `dns.` prefix.

Key files:
- `netgate.go` (imports ngdns for `Dnsname2Regexp`)
- `pkg/ngtls/certificate.go`
- `modules/dns/app.go` (self-import, remove or adjust)

- [ ] **Step 3: Fix any symbol references**

If files used `ngdns.Something`, they still work with the alias. If they used unaliased import, update call sites to `dns.Something`.

- [ ] **Step 4: Build and verify**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/ngdns into modules/dns"
```

### Task 6: Move `pkg/ngtcp` → `modules/ngtcp` (merge with `modules/tcp`)

**Files:**
- Move: all `pkg/ngtcp/*.go` (controller.go, proxy.go, detect.go, proxyprotocol.go, types.go, conn.go) → `modules/tcp/`
- Modify: `modules/tcp/app.go` package declaration and imports
- Note: `pkg/ngtcp` is `package ngtcp`, `modules/tcp` is `package tcp`. Keep `ngtcp` as package name (to avoid shadowing). Rename `modules/tcp/` directory to `modules/ngtcp/`.

- [ ] **Step 1: Rename directory and move files**

```bash
mv modules/tcp modules/ngtcp
mv pkg/ngtcp/*.go modules/ngtcp/
```

Edit `modules/ngtcp/app.go`: change `package tcp` to `package ngtcp`.

- [ ] **Step 2: Update all import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/ngtcp"` with `"github.com/mrhaoxx/OpenNG/modules/ngtcp"`.
Replace `"github.com/mrhaoxx/OpenNG/modules/tcp"` with `"github.com/mrhaoxx/OpenNG/modules/ngtcp"`.

Update `cmd/netgate/main.go` blank import.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/ngtcp into modules/ngtcp"
```

### Task 7: Move `pkg/nghttp` → `modules/nghttp` (merge with `modules/http`)

**Files:**
- Move: all `pkg/nghttp/*.go` → `modules/http/`
- Move: `pkg/nghttp/html/` → `modules/http/html/` (HTML templates)
- Rename: `modules/http/` → `modules/nghttp/`

- [ ] **Step 1: Rename directory and move files**

```bash
mv modules/http modules/nghttp
mv pkg/nghttp/*.go modules/nghttp/
mv pkg/nghttp/html modules/nghttp/html
```

Edit `modules/nghttp/app.go`: change `package http` to `package nghttp`. Remove dot-import of self (`"github.com/mrhaoxx/OpenNG/pkg/nghttp"`).

- [ ] **Step 2: Update all import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/nghttp"` with `"github.com/mrhaoxx/OpenNG/modules/nghttp"`.
Replace `"github.com/mrhaoxx/OpenNG/modules/http"` with `"github.com/mrhaoxx/OpenNG/modules/nghttp"`.

- [ ] **Step 3: Fix dot-imports and aliases**

`modules/nghttp/app.go` currently does `. "github.com/mrhaoxx/OpenNG/pkg/nghttp"` — remove this since the symbols are now in the same package.

Other files using `nghttp "..."` or `. "..."` — update the paths.

- [ ] **Step 4: Build and verify**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/nghttp into modules/nghttp"
```

### Task 8: Move `pkg/ngtls` → `modules/ngtls` (merge with `modules/tls`)

**Files:**
- Move: `pkg/ngtls/certificate.go`, `pkg/ngtls/tcp.go` → `modules/tls/`
- Rename: `modules/tls/` → `modules/ngtls/`

- [ ] **Step 1: Rename and move**

```bash
mv modules/tls modules/ngtls
mv pkg/ngtls/*.go modules/ngtls/
```

Edit `modules/ngtls/app.go`: change `package tls` to `package ngtls`. Remove dot-import of self.

- [ ] **Step 2: Update import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/ngtls"` with `"github.com/mrhaoxx/OpenNG/modules/ngtls"`.
Replace `"github.com/mrhaoxx/OpenNG/modules/tls"` with `"github.com/mrhaoxx/OpenNG/modules/ngtls"`.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/ngtls into modules/ngtls"
```

### Task 9: Move `pkg/ngssh` → `modules/ngssh` (merge with `modules/ssh`)

**Files:**
- Move: `pkg/ngssh/midware.go`, `pkg/ngssh/proxy.go` → `modules/ssh/`
- Rename: `modules/ssh/` → `modules/ngssh/`

- [ ] **Step 1: Rename and move**

```bash
mv modules/ssh modules/ngssh
mv pkg/ngssh/*.go modules/ngssh/
```

Edit `modules/ngssh/app.go`: change `package ssh` to `package ngssh`.

- [ ] **Step 2: Update import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/ngssh"` with `"github.com/mrhaoxx/OpenNG/modules/ngssh"`.
Replace `"github.com/mrhaoxx/OpenNG/modules/ssh"` with `"github.com/mrhaoxx/OpenNG/modules/ngssh"`.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/ngssh into modules/ngssh"
```

### Task 10: Move `pkg/expr` → `modules/expr`

**Files:**
- Move: `pkg/expr/*.go` → `modules/expr/`

- [ ] **Step 1: Move files**

```bash
mv pkg/expr/*.go modules/expr/
```

Both are already `package expr` or similar — verify package declaration matches.

- [ ] **Step 2: Update import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/expr"` with `"github.com/mrhaoxx/OpenNG/modules/expr"`.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/expr into modules/expr"
```

### Task 11: Move `pkg/auth` → `modules/auth`

**Files:**
- Move: `pkg/auth/*.go` and `pkg/auth/html/` → `modules/auth/`
- Move: `pkg/auth/backend/*.go` → `modules/auth/backend/`

- [ ] **Step 1: Move files**

```bash
mv pkg/auth/backend modules/auth/backend
mv pkg/auth/*.go modules/auth/
mv pkg/auth/html modules/auth/html
```

Verify `modules/auth/app.go` and moved files are both `package auth`. If `pkg/auth` was a different package name, rename.

- [ ] **Step 2: Update import paths**

Replace `"github.com/mrhaoxx/OpenNG/pkg/auth"` with `"github.com/mrhaoxx/OpenNG/modules/auth"`.
Replace `"github.com/mrhaoxx/OpenNG/pkg/auth/backend"` with `"github.com/mrhaoxx/OpenNG/modules/auth/backend"`.

`modules/auth/app.go` currently imports `authsdk "github.com/mrhaoxx/OpenNG/pkg/auth"` — remove this self-import and use symbols directly.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/auth into modules/auth"
```

### Task 12: Move `pkg/misc` → `modules/misc`

**Files:**
- Move: `pkg/misc/*.go` → `modules/misc/`

- [ ] **Step 1: Move and update**

```bash
mv pkg/misc/*.go modules/misc/
```

Replace `"github.com/mrhaoxx/OpenNG/pkg/misc"` with `"github.com/mrhaoxx/OpenNG/modules/misc"`.

- [ ] **Step 2: Build and verify**

```bash
go build ./...
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/misc into modules/misc"
```

### Task 13: Move `pkg/tunnels` → `modules/tunnels`

**Files:**
- Move: `pkg/tunnels/tunnel.go` → `modules/tunnels/tunnel.go`
- Move: `pkg/tunnels/http/*.go` → `modules/tunnels/http/`
- Move: `pkg/tunnels/trojan/*.go` → `modules/tunnels/trojan/`
- Move: `pkg/tunnels/wireguard/*.go` → `modules/tunnels/wireguard/`

- [ ] **Step 1: Move all files**

```bash
mv pkg/tunnels/tunnel.go modules/tunnels/tunnel.go
mv pkg/tunnels/http/*.go modules/tunnels/http/
mv pkg/tunnels/trojan/*.go modules/tunnels/trojan/
mv pkg/tunnels/wireguard/*.go modules/tunnels/wireguard/
```

Check package declarations match in each subdirectory.

- [ ] **Step 2: Update import paths**

Replace all `"github.com/mrhaoxx/OpenNG/pkg/tunnels` prefixed imports with `"github.com/mrhaoxx/OpenNG/modules/tunnels`.

- [ ] **Step 3: Build and verify**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: merge pkg/tunnels into modules/tunnels"
```

### Task 14: Remove empty `pkg/` directory and verify

- [ ] **Step 1: Verify pkg/ is empty**

```bash
find pkg/ -name '*.go' | head
```

Expected: no output. All `.go` files have been moved.

- [ ] **Step 2: Remove pkg/**

```bash
rm -rf pkg/
```

- [ ] **Step 3: Final full build**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: remove empty pkg/ directory"
```

---

## Part 2: mTLS Decoupling

### Task 15: Remove `CheckClientCert` from `PolicyBackend` interface

**Files:**
- Modify: `modules/auth/policybase.go` — remove `CheckClientCert` from interface, remove from `backendGroup`
- Modify: `modules/auth/backend/file.go` — remove `CheckClientCert` method, remove `clientCertFPs` field, remove `certFPIndex`, revert `SetUser` signature
- Modify: `modules/auth/backend/ldap.go` — remove `CheckClientCert` method

- [ ] **Step 1: Remove from `PolicyBackend` interface**

In `modules/auth/policybase.go`, change:

```go
type PolicyBackend interface {
	CheckPassword(username string, password string) bool
	CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) bool
	CheckClientCert(fingerprint string) (username string, ok bool)
	AllowForwardProxy(username string) bool
	ExistsUser(username string) bool
}
```

to:

```go
type PolicyBackend interface {
	CheckPassword(username string, password string) bool
	ExistsUser(username string) bool
}

type SSHKeyChecker interface {
	CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) bool
}

type ForwardProxyAuthorizer interface {
	AllowForwardProxy(username string) bool
}
```

- [ ] **Step 2: Update `backendGroup` methods**

Change `backendGroup.CheckSSHKey` to use type assertion:

```go
func (b backendGroup) CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) (bool, int) {
	for i, backend := range b {
		if checker, ok := backend.(SSHKeyChecker); ok {
			if checker.CheckSSHKey(ctx, key) {
				return true, i
			}
		}
	}
	return false, -1
}
```

Same for `AllowForwardProxy`:

```go
func (b backendGroup) AllowForwardProxy(username string) (bool, int) {
	for i, backend := range b {
		if auth, ok := backend.(ForwardProxyAuthorizer); ok {
			if auth.AllowForwardProxy(username) {
				return true, i
			}
		}
	}
	return false, -1
}
```

Remove `backendGroup.CheckClientCert` entirely.

- [ ] **Step 3: Remove from file backend**

In `modules/auth/backend/file.go`:
- Remove `clientCertFPs` field from `user` struct
- Remove `certFPIndex` field from `fileBackend` struct
- Remove `CheckClientCert` method
- Revert `SetUser` signature to remove `clientCertFPs` parameter
- Remove `certFPIndex` initialization from `NewFileBackend`

- [ ] **Step 4: Remove from LDAP backend**

In `modules/auth/backend/ldap.go`: remove the `CheckClientCert` method.

- [ ] **Step 5: Add cert mapping to policyBaseAuth**

In `modules/auth/policybase.go`, add to `policyBaseAuth` struct:

```go
type policyBaseAuth struct {
	// ... existing fields
	certMappings      map[string]string // SHA256 fingerprint → username
	forwardProxyUsers map[string]bool
}
```

Update `HandleAuth` to check cert mapping when no session exists (the logic currently in the unstaged changes, but reading from `policyBaseAuth.certMappings` instead of calling `backends.CheckClientCert`).

- [ ] **Step 6: Update auth module registration**

In `modules/auth/app.go`:
- Remove `ClientCertFingerprints` from the file backend Assert and `SetUser` call
- Add `CertMappings` and `ForwardProxyUsers` to `auth::policyd` Assert and parsing

- [ ] **Step 7: Build and verify**

```bash
go build ./...
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor: decouple mTLS and forward proxy from PolicyBackend interface"
```

---

## Part 3: Admin Extensibility

### Task 16: Add `AdminProvider` and Widget types to root package

**Files:**
- Create: `admin.go` (in root package, alongside `netgate.go`)

- [ ] **Step 1: Create `admin.go`**

```go
package ng

import (
	"encoding/json"
	stdhttp "net/http"
)

// AdminContext is satisfied by *nghttp.HttpCtx via structural typing.
type AdminContext interface {
	stdhttp.ResponseWriter
	Request() *stdhttp.Request
}

func WriteJSON(w stdhttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type AdminHandler func(AdminContext)

type AdminProvider interface {
	AdminMeta() AdminMeta
}

type AdminMeta struct {
	Name     string       `json:"name"`
	Title    string       `json:"title"`
	Category string       `json:"category"`
	Icon     string       `json:"icon,omitempty"`
	Priority int          `json:"priority,omitempty"`
	Root     Widget       `json:"root"`
	Routes   []AdminRoute `json:"routes"`
}

type AdminRoute struct {
	Method  string       `json:"-"`
	Path    string       `json:"-"`
	Desc    string       `json:"desc,omitempty"`
	Handler AdminHandler `json:"-"`
}
```

- [ ] **Step 2: Create `widget.go`**

Create `widget.go` in root package with `WidgetContent` interface, `Widget` struct with `MarshalJSON`, all concrete widget types (Table, Stat, Action, Stream, Code, KV, Form, Text, Chart, Detail, Toggle), layout types (columnsLayout, columnLayout, cardLayout, tabsLayout, tabLayout, rowLayout), and layout helper functions (Columns, Column, Card, Tabs, Tab, Row).

Also add `ColumnDef`, `FieldDef`, `ActionDef`, `OptionDef` structs.

(Full code as specified in the design spec section 3.3–3.5)

- [ ] **Step 3: Add `Request()` method to `HttpCtx`**

In `modules/nghttp/http.go`, add:

```go
func (ctx *HttpCtx) Request() *stdhttp.Request {
	return ctx.Req
}
```

This makes `*HttpCtx` satisfy `AdminContext` structurally (it already embeds a response writer).

Verify `HttpCtx.Resp` satisfies `http.ResponseWriter` — check the `NgResponseWriter` type.

- [ ] **Step 4: Build and verify**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add AdminProvider interface and Widget type system to root package"
```

### Task 17: Refactor admin module to use `AdminProvider` discovery

**Files:**
- Modify: `modules/admin/ui.go` — remove hard-coded imports of ngtls, auth/backend; discover AdminProvider from Space
- Modify: `modules/admin/app.go` — pass Space to UI struct

This task changes admin to discover capabilities at runtime instead of importing specific modules. The admin module still needs `nghttp` (it's an HTTP service) and `ngcmd` (for config access), but drops `ngtls`, `auth/backend`, `groupexp`.

- [ ] **Step 1: Update UI struct**

Replace hard-coded module references with discovered providers:

```go
type UI struct {
	providers []ng.AdminProvider
}
```

Remove `TcpController Reporter`, `HttpMidware Reporter`, `TlsMgr *ngtls.TlsMgr` fields.

- [ ] **Step 2: Add provider discovery**

Add method to collect providers from Space:

```go
func (u *UI) DiscoverProviders(services map[string]any) {
	for _, svc := range services {
		if p, ok := svc.(ng.AdminProvider); ok {
			u.providers = append(u.providers, p)
		}
	}
}
```

- [ ] **Step 3: Add `/api/v1/admin/modules` endpoint**

In `HandleHTTP`, add a new case that serializes all provider metadata as JSON:

```go
case "/api/v1/admin/modules":
	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.Header().Set("Cache-Control", "no-cache")
	var metas []ng.AdminMeta
	for _, p := range u.providers {
		metas = append(metas, p.AdminMeta())
	}
	json.NewEncoder(ctx.Resp).Encode(metas)
```

- [ ] **Step 4: Mount provider routes**

Add route mounting logic — when a request path matches a provider's AdminRoute, dispatch to that route's handler:

```go
func (u *UI) handleProviderRoute(ctx *nghttp.HttpCtx) bool {
	for _, p := range u.providers {
		meta := p.AdminMeta()
		for _, route := range meta.Routes {
			if ctx.Req.URL.Path == route.Path && ctx.Req.Method == route.Method {
				route.Handler(ctx)
				return true
			}
		}
	}
	return false
}
```

Call this from `HandleHTTP` before the existing switch statement.

- [ ] **Step 5: Update admin registration**

In `modules/admin/app.go`, update the factory function to accept Space and call `DiscoverProviders`.

- [ ] **Step 6: Remove unused imports**

Remove imports of `ngtls`, `auth/backend`, `groupexp` from `modules/admin/ui.go`. Remove the `Reporter` interface.

- [ ] **Step 7: Build and verify**

```bash
go build ./...
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: admin discovers modules via AdminProvider interface"
```

---

## Notes

- **Frontend SPA** (replacing multi-page HTML with Preact + dynamic widget rendering) is a separate effort. This plan only adds the backend types and discovery mechanism. The existing admin HTML pages continue to work.
- **Existing admin endpoints** (`/api/v1/connections`, `/api/v1/requests`, `/api/v1/config`, etc.) remain as-is until modules implement `AdminProvider` and the SPA is built. The admin module can keep its existing endpoints alongside the new discovery endpoint during transition.
- Each Part is independently mergeable. Part 1 (directory merge) is pure refactoring with no behavior change. Part 2 (mTLS) is a breaking config change. Part 3 (admin) adds new types and changes admin wiring but doesn't remove existing functionality.
