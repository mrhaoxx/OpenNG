# Two-Phase Space.Apply Implementation Plan

**Goal:** Make config entry order irrelevant by splitting Apply into parse-all → topo-sort → instantiate.

**Architecture:** Keep existing config format, $dref, ptr, Assert, ArgNode. Only change `instance.go`'s `Apply` method from single-pass to two-phase. No module changes needed.

---

### Task 1: Add `collectDeps` — extract ptr references from an ArgNode tree

**File:** `instance.go`

After `AssertArg` runs, ptr fields have `Type="ptr"` with `Value` as a string (service name). URL fields have `Type="url"` with `Value.(*ngnet.URL).Interface` as a service name.

Write a function that walks an ArgNode tree and collects all service name references:

```go
func collectDeps(node *ArgNode, assert Assert) []string {
    var deps []string
    // Walk tree, for each node:
    //   Type=="ptr" && Value is string → append Value
    //   Type=="url" && Value.(*ngnet.URL).Interface != "" → append Interface
    //   Type=="map" → recurse into sub-nodes using assert.Sub
    //   Type=="list" → recurse into list items using assert.Sub["_"]
    return deps
}
```

Skip anonymous inline ptrs (Value is map, not string) — those don't reference named services.

- [ ] Write `collectDeps`
- [ ] Verify it handles: ptr strings, url interfaces, nested maps, lists, nil nodes

### Task 2: Add topological sort

**File:** `instance.go`

```go
func topoSort(entries []entry, deps map[int][]int) ([]int, error)
```

Input: list of entries + dependency adjacency list (entry index → indices it depends on).
Output: ordered indices (dependencies first) or error if cycle detected.

Standard Kahn's algorithm:
- Compute in-degrees
- Start with zero in-degree entries
- BFS, decrement in-degrees
- If remaining entries have non-zero in-degree → cycle error

- [ ] Write `topoSort`
- [ ] Handle cycle detection with clear error message (which entries form the cycle)

### Task 3: Refactor Apply into two phases

**File:** `instance.go`

Define an internal struct for collected entries:

```go
type serviceEntry struct {
    index   int
    kind    string
    name    string
    spec    *ArgNode
    ref     Inst
    assert  Assert
    deps    []string   // service names this entry depends on
}
```

**Phase 1: Collect and validate**

```go
// Collect all entries
var entries []serviceEntry
for i, _srv := range srvs.Value.([]*ArgNode) {
    kind := _srv.MustGet("kind").ToString()
    name := _srv.MustGet("name").ToString()
    spec := _srv.MustGet("spec")
    
    ref, ok := space.Refs[kind]
    // ... error handling
    
    assert, ok := space.AssertRefs[kind]
    // ... error handling
    
    err := AssertArg(spec, assert)
    // ... error handling
    
    deps := collectDeps(spec, assert)
    
    entries = append(entries, serviceEntry{
        index: i, kind: kind, name: name,
        spec: spec, ref: ref, assert: assert,
        deps: deps,
    })
}
```

**Build dependency graph:**

```go
// Map service name → entry index (only named services)
nameToIdx := map[string]int{}
for i, e := range entries {
    if e.name != "" && e.name != "_" {
        nameToIdx[e.name] = i
    }
}

// Build adjacency: entry i depends on entry j
adjDeps := map[int][]int{}
for i, e := range entries {
    for _, depName := range e.deps {
        if j, ok := nameToIdx[depName]; ok {
            adjDeps[i] = append(adjDeps[i], j)
        }
        // If depName not in nameToIdx, it's a pre-populated service (sys, @) — skip
    }
}
```

**Topo sort:**

```go
order, err := topoSort(entries, adjDeps)
if err != nil {
    return fmt.Errorf("circular dependency: %w", err)
}
```

**Phase 2: Instantiate in order**

```go
for _, idx := range order {
    e := entries[idx]
    
    err := space.Deptr(e.spec, dry, e.assert, e.name)
    // ... error handling (same as current)
    
    var inst any
    if !dry {
        inst, err = e.ref(e.spec)
    }
    // ... error handling (same as current)
    
    if e.name != "" && e.name != "_" && inst != nil {
        space.Services[e.name] = inst
        space.ServiceKinds[e.name] = e.kind
    }
    
    log.Info()...
}
```

**Key changes from current code:**
- `AssertArg` runs for ALL entries before ANY `Deptr`/instantiation
- `Deptr` + instantiation runs in dependency order, not config file order
- Error handling for reload mode stays the same

- [ ] Refactor Apply into two phases
- [ ] Keep reload error handling (continue on error, collect errors)
- [ ] Keep dry mode support
- [ ] Keep edge tracking (addEdge in Deptr)
- [ ] Keep logging per service

### Task 4: Handle edge cases

- [ ] **Pre-populated services**: `sys` and `@` are in Space.Services before Apply. Deps referencing them should be satisfied without needing an entry.

- [ ] **name="_" entries**: Actions without names. They have deps but nobody depends on them. They go after their deps in topo sort but don't add themselves to nameToIdx.

- [ ] **Multiple entries with same name**: Currently last one wins. Preserve this — if two entries have the same name, the second overwrites.

- [ ] **Anonymous inline ptrs**: `Deptr` handles these via `instantiateAnon`. collectDeps should NOT try to resolve these — they're inline, not references. Just skip ptr nodes where Value is map, not string.

- [ ] **Entries with no deps**: Go first (or in original config order among peers at same topo level).

- [ ] **Stable sort**: Among entries at the same dependency level, preserve original config order.

### Task 5: Build and test

- [ ] `go build ./...`
- [ ] Run the actual program with the existing config
- [ ] Verify: reorder some entries in config.yaml and confirm it still works
- [ ] Verify: Space Map shows correct edges

### Task 6: Commit

```
git add instance.go
git -c commit.gpgsign=false commit -m "refactor: two-phase Space.Apply — config order no longer matters

Phase 1: parse all entries, validate schemas, collect dependencies
Phase 2: topological sort by ptr/url references, instantiate in order

This eliminates the requirement that services must be defined
before they are referenced in the config file."
```
