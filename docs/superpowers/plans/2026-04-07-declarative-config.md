# Declarative Config Implementation Plan

**Goal:** Config 从有序列表改为无序 map-by-name，两阶段 Apply（收集 → 拓扑排序 → 实例化），删除 action kinds。

**Breaking change:** 配置格式、模块注册 API 都会变。

---

### Task 1: 新配置格式解析

**Files:** `cmd/parser.go`, `cmd/config.go`

旧格式：
```yaml
Services:
  - kind: tls
    name: tls
    spec:
      Certificates: [...]
```

新格式：
```yaml
Services:
  tls:
    kind: tls
    Certificates: [...]
```

改动：
- `TopLevelConfigAssertion` 的 `Services` 从 list 改为 map
- `Services` 的 map value Assert: `{Type: "map", Sub: {"kind": {Type: "string", Required: true}, "_": {Type: "any"}}}`
- `Space.Apply` 的输入从 `[]*ArgNode` 改为 `map[string]*ArgNode`

每个 entry 的 name 是 map key，kind 是 entry 内的字段，其余字段就是 spec（不再有 `spec` 嵌套层）。

- [ ] 修改 `TopLevelConfigAssertion`
- [ ] 修改 `LoadCfg` 和 `ValidateCfg`
- [ ] 修改 `Space.Apply` 签名

### Task 2: 两阶段 Apply

**File:** `instance.go`

```go
func (space *Space) Apply(services map[string]*ArgNode, reload bool, dry bool) error
```

**Phase 1: 收集**

```go
type serviceEntry struct {
    name   string
    kind   string
    spec   *ArgNode    // kind 字段去掉后的 map
    ref    Inst
    assert Assert
    deps   []string    // 从 spec 中提取的 ptr 引用名
}
```

对每个 entry：
1. 提取 `kind` 字段，从 map 中删除
2. 剩余字段作为 spec
3. 查找 `space.Refs[kind]` 和 `space.AssertRefs[kind]`
4. `AssertArg(spec, assert)` — schema 校验 + 类型转换
5. `collectDeps(spec, assert)` — 扫描 spec 树中所有 ptr 字符串引用名

**collectDeps 实现：**

遍历 ArgNode 树，收集：
- `Type=="ptr"` 且 `Value` 是 string → 服务名引用
- `Type=="url"` 且 `Value.(*ngnet.URL).Interface != ""` → 接口引用
- 递归进入 map 和 list 子节点

**Phase 2: 拓扑排序 + 实例化**

1. 建依赖图：entry name → 它引用的 entry names（跳过预置服务 sys、@）
2. Kahn 算法拓扑排序，环检测报错
3. 按排序后的顺序：
   - `Deptr(spec, ...)` — 解析 ptr 为实际对象
   - `ref(spec)` — 调用工厂函数
   - `Services[name] = inst`（仅 inst != nil）

- [ ] 实现 `collectDeps`
- [ ] 实现 `topoSort`（Kahn 算法 + 环检测 + 同级保持原始 map 遍历顺序）
- [ ] 重写 `Apply`

### Task 3: 删除 action kinds

**Files:** 各模块 app.go

**3a. `http::midware::addservice` → 删除**

`http::midware` 已经有 `MidwareConfig.Service` 字段，`NewHttpMidware` 已经处理了 services。`addservice` 不再需要。

- [ ] 从 `modules/nghttp/app.go` 删除 `registerMidwareAddService()`

**3b. `wireguard::addpeers` → 合并到 wireguard::server**

在 `WireGuardConfig` 里加 `Peers` 字段，`NewWireGuardServer` 里调用 `AddPeer`。

- [ ] 修改 `modules/tunnels/wireguard/app.go`

**3c. `tls::reload` → 删除**

启动时证书本来就是新加载的。

- [ ] 从 `modules/ngtls/app.go` 删除 `tls::reload` 注册

**3d. `log::set/add/reset` → 移到 Config.Logger**

在 `GlobalCfg` 里处理 Logger.Outputs：
```yaml
Config:
  Logger:
    Outputs: [stdout, "/var/log/ng.log"]
```

遍历 Outputs：
- `"stdout"` → `os.Stdout`
- `"stderr"` → `os.Stderr`
- 其他字符串 → `os.OpenFile(path, ...)`

调用 `log.Loggers.Set(loggers)`。

保留 `log::stdout`、`log::stderr`、`log::file` 作为 service kinds（返回 Logger ptr，可被其他服务引用），但 `log::set/add/reset` 删除。

- [ ] 修改 `cmd/config.go` 的 `GlobalCfg`
- [ ] 修改 `TopLevelConfigAssertion` 加 Outputs
- [ ] 从 `modules/log/app.go` 删除 set/add/reset

**3e. `tcp::controller::Listen` → 合并到 controller spec**

`TcpControllerConfig` 加 `Listen []string` 字段。`NewTcpController` 末尾调用 `ctl.Listen(cfg.Listen)`。

由于拓扑排序保证 controller 最后创建，Listen 在构造函数末尾调用是安全的。

- [ ] 修改 `modules/ngtcp/controller.go` 的 `TcpControllerConfig` 和 `NewTcpController`
- [ ] `RegisterFunc` 的方法自动发现会自动注册 `Listen` 为子 kind——现在 Listen 在构造函数里调了，自动发现的子 kind 不影响（用户不再需要单独调用）

**3f. `dns::server` 的 `go server.Listen(listen)` → 同理**

DNS server 构造函数里直接 `go server.Listen()`，现在也安全了（拓扑排序保证依赖就绪）。不需要改。

### Task 4: spec 展开（去掉 spec 嵌套层）

**File:** `instance.go`

新格式里没有 `spec` 字段，kind 以外的所有字段直接就是 spec：

```yaml
Services:
  tls:
    kind: tls          # 框架字段
    Certificates: [...] # spec 字段
```

Apply 在 Phase 1 处理每个 entry 时：
1. 从 entry map 中取出 `kind` 字段
2. 剩余的 map 就是 spec

```go
entryMap := entry.ToMap()
kindNode := entryMap["kind"]
delete(entryMap, "kind")
spec := &ArgNode{Type: "map", Value: entryMap}
```

- [ ] 在 Apply Phase 1 中实现 kind 提取

### Task 5: 更新 admin 后端

**File:** `modules/admin/ui.go`

`/api/v1/cfg/schema` 生成的 JSON schema 需要反映新格式。
`/api/v1/space/map` 不需要改（Space.Services 的数据结构没变）。

- [ ] 验证 schema 生成是否自动适配新 Assert
- [ ] 验证 Space Map 正常

### Task 6: 构建和测试

- [ ] `go build ./...`
- [ ] 写一个新格式的测试 config
- [ ] 运行程序验证所有服务正常启动
- [ ] 验证调换 config 中 service 顺序不影响结果
- [ ] 验证 Space Map 显示正确

### Task 7: 提交

```
git -c commit.gpgsign=false commit -m "refactor: declarative config with two-phase Apply

- Config format: Services list → map-by-name, spec fields inline
- Two-phase Apply: collect + topo sort → instantiate in dependency order
- Config entry order no longer matters
- Removed action kinds: addservice, addpeers, tls::reload, log::set/add/reset
- tcp::controller::Listen merged into controller config
- Logger outputs moved to Config.Logger.Outputs"
```
