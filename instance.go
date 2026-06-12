package ng

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog/log"
)

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Space struct {
	Services     map[string]any
	AssertRefs   map[string]Assert
	Refs         map[string]Inst
	ServiceKinds map[string]string
	Edges        []Edge
	edgeSet      map[Edge]bool
}

func (space *Space) addEdge(from, to string) {
	e := Edge{From: from, To: to}
	if space.edgeSet == nil {
		space.edgeSet = make(map[Edge]bool)
	}
	if !space.edgeSet[e] {
		space.edgeSet[e] = true
		space.Edges = append(space.Edges, e)
	}
}

func (space *Space) Deptr(root *ArgNode, validate bool, _assert Assert, owner string) error {
	if root == nil {
		return nil
	}

	var walk func(*ArgNode, Assert) error
	walk = func(node *ArgNode, assert Assert) error {
		switch node.Type {
		case "map":
			for k, v := range node.ToMap() {
				if sub, ok := assert.Sub[k]; ok {
					err := walk(v, sub)
					if err != nil {
						return fmt.Errorf(".%s: %w", k, err)
					}
				} else if sub, ok := assert.Sub["_"]; ok {
					err := walk(v, sub)
					if err != nil {
						return fmt.Errorf(".%s: %w", k, err)
					}
				} else {
					err := walk(v, Assert{})
					if err != nil {
						return fmt.Errorf(".%s: %w", k, err)
					}
				}
			}
		case "list":
			for i, v := range node.ToList() {
				err := walk(v, assert.Sub["_"])
				if err != nil {
					return fmt.Errorf("[%d]: %w", i, err)
				}
			}
		case "url":
			if node.Value == nil {
				node.Value = []*ngnet.URL{}
				return nil
			}
			realnode, ok := node.Value.(*ngnet.URL)
			if !ok {
				return fmt.Errorf("expected url, got %T", node.Value)
			}
			if realnode.Interface != "" {
				v, ok := space.Services[realnode.Interface]
				if ok {
					if !validate {
						node.Value.(*ngnet.URL).Underlying = v.(ngnet.Interface)
						if owner != "" {
							space.addEdge(owner, realnode.Interface)
						}
					}
				} else {
					return fmt.Errorf("url interface not found: %s", realnode.Interface)
				}
			}
		case "ptr":
			switch v := node.Value.(type) {
			case string:
				if svc, ok := space.Services[v]; ok {
					node.Value = svc
					if !validate && owner != "" && v != "" {
						space.addEdge(owner, v)
					}
				} else {
					return fmt.Errorf("ptr not found: %s", v)
				}
			case map[string]*ArgNode:
				if validate {
					node.Value = nil
					break
				}
				inst, err := space.instantiateAnon(v, validate, owner)
				if err != nil {
					return err
				}
				node.Value = inst

			case *ArgNode:
				if v.Type != "map" {
					return fmt.Errorf("invalid anonymous ptr node type: %s", v.Type)
				}
				mm := v.Value.(map[string]*ArgNode)
				if validate {
					node.Value = nil
					break
				}
				inst, err := space.instantiateAnon(mm, validate, owner)
				if err != nil {
					return err
				}
				node.Value = inst
			default:
				return fmt.Errorf("ptr expects name or inline anonymous object, got %T", node.Value)
			}

			if validate {
				return nil
			}

			err := validateInterfaces(assert, node.Value)
			if err != nil {
				return err
			}
		}
		return nil
	}

	return walk(root, _assert)
}

func (space *Space) instantiateAnon(m map[string]*ArgNode, validate bool, owner string) (any, error) {
	var kind string
	if k, ok := m["kind"]; ok && k != nil {
		if k.Type != "string" {
			return nil, fmt.Errorf("anonymous object: kind must be string")
		}
		kind = k.ToString()
	} else {
		return nil, fmt.Errorf("anonymous object missing kind")
	}

	delete(m, "kind")
	var spec *ArgNode
	if len(m) == 0 {
		spec = &ArgNode{Type: "null", Value: nil}
	} else {
		spec = &ArgNode{Type: "map", Value: m}
	}

	specAssert, ok := space.AssertRefs[kind]
	if !ok {
		return nil, fmt.Errorf("assert not found: %s", kind)
	}
	if err := AssertArg(spec, specAssert); err != nil {
		return nil, fmt.Errorf("%s: assert failed: %w", kind, err)
	}

	if err := space.Deptr(spec, validate, specAssert, owner); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}

	ref, ok := space.Refs[kind]
	if !ok {
		return nil, fmt.Errorf("kind not found: %s", kind)
	}

	inst, err := safeInst(ref, spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	return inst, nil
}

// safeInst calls a constructor and converts panics into errors, so a faulty
// service constructor cannot crash a running gateway during hot reload.
func safeInst(ref Inst, spec *ArgNode) (inst any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("constructor panic: %v", r)
		}
	}()
	return ref(spec)
}

// collectDeps walks an ArgNode tree and collects all service names
// referenced by ptr (string) and url (Interface) fields.
func (space *Space) collectDeps(node *ArgNode, assert Assert) []string {
	if node == nil {
		return nil
	}
	var deps []string
	var walk func(*ArgNode, Assert)
	walk = func(n *ArgNode, a Assert) {
		if n == nil {
			return
		}
		switch n.Type {
		case "ptr":
			if name, ok := n.Value.(string); ok && name != "" {
				deps = append(deps, name)
			} else if m, ok := n.Value.(map[string]*ArgNode); ok {
				if kindNode := m["kind"]; kindNode != nil && kindNode.Type == "string" {
					kind := kindNode.ToString()
					// Build spec from remaining fields (flattened)
					spec := &ArgNode{Type: "null"}
					if len(m) > 1 { // more than just "kind"
						remaining := make(map[string]*ArgNode, len(m)-1)
						for k, v := range m {
							if k != "kind" {
								remaining[k] = v
							}
						}
						spec = &ArgNode{Type: "map", Value: remaining}
					}
					if a, ok := space.AssertRefs[kind]; ok {
						walk(spec, a)
					}
				}
			}
		case "url":
			if u, ok := n.Value.(*ngnet.URL); ok && u != nil && u.Interface != "" {
				deps = append(deps, u.Interface)
			}
		case "map":
			if m, ok := n.Value.(map[string]*ArgNode); ok {
				for k, v := range m {
					if sub, ok := a.Sub[k]; ok {
						walk(v, sub)
					} else if sub, ok := a.Sub["_"]; ok {
						walk(v, sub)
					}
				}
			}
		case "list":
			if items, ok := n.Value.([]*ArgNode); ok {
				subAssert := a.Sub["_"]
				for _, item := range items {
					walk(item, subAssert)
				}
			}
		}
	}
	walk(node, assert)
	return deps
}

type serviceEntry struct {
	name   string
	kind   string
	spec   *ArgNode
	ref    Inst
	assert Assert
	deps   []string
}

// topoSort returns indices in dependency order (dependencies first).
// Returns error if a cycle is detected.
func topoSort(entries []serviceEntry, prePopulated map[string]bool) ([]int, error) {
	nameToIdx := map[string]int{}
	for i, e := range entries {
		nameToIdx[e.name] = i
	}

	// Build in-degree count and adjacency
	inDegree := make([]int, len(entries))
	dependents := make([][]int, len(entries)) // dependents[j] = entries that depend on j
	for i := range dependents {
		dependents[i] = nil
	}

	for i, e := range entries {
		for _, dep := range e.deps {
			if prePopulated[dep] {
				continue // sys, @ etc — already exist
			}
			j, ok := nameToIdx[dep]
			if !ok {
				continue // will fail at Deptr time
			}
			inDegree[i]++
			dependents[j] = append(dependents[j], i)
		}
	}

	// Kahn's algorithm
	var queue []int
	for i, d := range inDegree {
		if d == 0 {
			queue = append(queue, i)
		}
	}

	var order []int
	for len(queue) > 0 {
		idx := queue[0]
		queue = queue[1:]
		order = append(order, idx)
		for _, dep := range dependents[idx] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(order) != len(entries) {
		// Find cycle participants for error message
		var cycleNames []string
		for i, d := range inDegree {
			if d > 0 {
				cycleNames = append(cycleNames, entries[i].name+" ("+entries[i].kind+")")
			}
		}
		return nil, fmt.Errorf("circular dependency involving: %s", strings.Join(cycleNames, ", "))
	}

	return order, nil
}

// ConfigError is a structured validation error for a specific service.
type ConfigError struct {
	Service string `json:"service"`          // service name
	Kind    string `json:"kind,omitempty"`   // service kind
	Phase   string `json:"phase"`            // "parse", "schema", "reference", "dependency", "instantiate"
	Message string `json:"message"`
}

func (e ConfigError) Error() string {
	if e.Service != "" {
		return fmt.Sprintf("%s (%s): %s", e.Service, e.Kind, e.Message)
	}
	return e.Message
}

// ptrRef is a ptr reference found during validation: source service references target by name,
// requiring certain interfaces.
type ptrRef struct {
	target     string         // service name (named ref) or empty (inline)
	inlineKind string         // kind name for inline anonymous objects
	impls      []reflect.Type
	fieldPath  string
}

// Validate checks the entire config tree and returns all errors found.
// Unlike Apply, it does not stop at the first error and does not instantiate services.
// It performs: schema validation, reference existence, static type checking, and cycle detection.
func (space *Space) Validate(root *ArgNode) []ConfigError {
	var errs []ConfigError
	retAsserts := ReturnAssertionsRegistry()

	srvs := root.MustGet("Services")
	if srvs == nil || srvs.Type != "map" {
		return []ConfigError{{Phase: "parse", Message: fmt.Sprintf("Services must be a map, got %s", srvs.Type)}}
	}

	type validEntry struct {
		serviceEntry
		refs []ptrRef
	}

	// Phase 1: parse + schema validation (collect all errors)
	var entries []validEntry
	kindByName := map[string]string{} // service name → kind
	for name, entry := range srvs.ToMap() {
		entryMap := entry.ToMap()
		kindNode, ok := entryMap["kind"]
		if !ok || kindNode == nil {
			errs = append(errs, ConfigError{Service: name, Phase: "parse", Message: "missing kind"})
			continue
		}
		kind := kindNode.ToString()
		delete(entryMap, "kind")

		var spec *ArgNode
		if len(entryMap) == 0 {
			spec = &ArgNode{Type: "null", Value: nil}
		} else {
			spec = &ArgNode{Type: "map", Value: entryMap}
		}

		_, refOk := space.Refs[kind]
		assert, assertOk := space.AssertRefs[kind]
		if !refOk || !assertOk {
			errs = append(errs, ConfigError{Service: name, Kind: kind, Phase: "parse", Message: "unknown kind: " + kind})
			continue
		}

		if err := AssertArg(spec, assert); err != nil {
			errs = append(errs, ConfigError{Service: name, Kind: kind, Phase: "schema", Message: err.Error()})
			continue
		}

		// Validate inline ptr objects' fields against their kind's schema
		inlineErrs := validateInlinePtrs(spec, assert, space.AssertRefs, "")
		for _, ie := range inlineErrs {
			errs = append(errs, ConfigError{Service: name, Kind: kind, Phase: "schema", Message: ie})
		}

		deps := space.collectDeps(spec, assert)
		refs := collectPtrRefs(spec, assert, space.AssertRefs)
		kindByName[name] = kind

		entries = append(entries, validEntry{
			serviceEntry: serviceEntry{
				name: name, kind: kind, spec: spec,
				ref: nil, assert: assert, deps: deps,
			},
			refs: refs,
		})
	}

	// Phase 2: reference existence + static type checking
	prePopulated := map[string]bool{}
	for name := range space.Services {
		prePopulated[name] = true
	}
	allNames := map[string]bool{}
	for k := range prePopulated {
		allNames[k] = true
	}
	for _, e := range entries {
		allNames[e.name] = true
	}

	for _, e := range entries {
		for _, ref := range e.refs {
			// Determine target kind for type checking
			var targetKind string
			if ref.inlineKind != "" {
				// Inline anonymous object — kind is known directly
				targetKind = ref.inlineKind
			} else {
				// Named service reference — check existence first
				if !allNames[ref.target] {
					errs = append(errs, ConfigError{
						Service: e.name, Kind: e.kind, Phase: "reference",
						Message: fmt.Sprintf("%s: references undefined service %q", ref.fieldPath, ref.target),
					})
					continue
				}
				var ok bool
				targetKind, ok = kindByName[ref.target]
				if !ok {
					continue // pre-populated service, skip type check
				}
			}

			// Static type check
			if len(ref.impls) == 0 {
				continue
			}
			retAssert, ok := retAsserts[targetKind]
			if !ok || len(retAssert.Impls) == 0 {
				continue
			}

			targetLabel := ref.target
			if ref.inlineKind != "" {
				targetLabel = "inline " + ref.inlineKind
			}

			for _, required := range ref.impls {
				if required.Kind() != reflect.Interface {
					continue
				}
				satisfied := false
				for _, provided := range retAssert.Impls {
					if provided.Implements(required) || reflect.PointerTo(provided).Implements(required) {
						satisfied = true
						break
					}
				}
				if !satisfied {
					provided := make([]string, len(retAssert.Impls))
					for i, t := range retAssert.Impls {
						provided[i] = t.String()
					}
					errs = append(errs, ConfigError{
						Service: e.name, Kind: e.kind, Phase: "type",
						Message: fmt.Sprintf("%s: %s (kind %s) does not implement %v (provides %v)",
							ref.fieldPath, targetLabel, targetKind, required, provided),
					})
				}
			}
		}
	}

	// Phase 3: cycle detection
	svcEntries := make([]serviceEntry, len(entries))
	for i, e := range entries {
		svcEntries[i] = e.serviceEntry
	}
	if _, err := topoSort(svcEntries, prePopulated); err != nil {
		errs = append(errs, ConfigError{Phase: "dependency", Message: err.Error()})
	}

	return errs
}

// validateInlinePtrs recursively validates inline ptr objects' fields against their kind's schema.
func validateInlinePtrs(node *ArgNode, assert Assert, assertRefs map[string]Assert, path string) []string {
	if node == nil {
		return nil
	}
	var errs []string
	var walk func(*ArgNode, Assert, string, int)
	walk = func(n *ArgNode, a Assert, p string, depth int) {
		if depth > 20 {
			return
		}
		if n == nil {
			return
		}
		switch n.Type {
		case "ptr":
			if m, ok := n.Value.(map[string]*ArgNode); ok {
				if kindNode := m["kind"]; kindNode != nil && kindNode.Type == "string" {
					kind := kindNode.ToString()
					sub, ok := assertRefs[kind]
					if !ok {
						errs = append(errs, fmt.Sprintf("%s: unknown inline kind %q", p, kind))
						return
					}
					spec := &ArgNode{Type: "null"}
					if len(m) > 1 {
						remaining := make(map[string]*ArgNode, len(m)-1)
						for k, v := range m {
							if k != "kind" {
								remaining[k] = v
							}
						}
						spec = &ArgNode{Type: "map", Value: remaining}
					}
					if err := AssertArg(spec, sub); err != nil {
						errs = append(errs, fmt.Sprintf("%s (inline %s): %s", p, kind, err.Error()))
					}
					// Recurse into the inline object's fields
					walk(spec, sub, p, depth+1)
				}
			}
		case "map":
			if m, ok := n.Value.(map[string]*ArgNode); ok {
				for k, v := range m {
					sub := Assert{}
					if s, ok := a.Sub[k]; ok {
						sub = s
					} else if s, ok := a.Sub["_"]; ok {
						sub = s
					} else {
						continue
					}
					walk(v, sub, p+"."+k, depth+1)
				}
			}
		case "list":
			if items, ok := n.Value.([]*ArgNode); ok {
				for i, item := range items {
					sub := Assert{}
					if i < len(a.SubList) {
						sub = a.SubList[i]
					} else if s, ok := a.Sub["_"]; ok {
						sub = s
					} else {
						continue
					}
					walk(item, sub, fmt.Sprintf("%s[%d]", p, i), depth+1)
				}
			}
		}
	}
	walk(node, assert, path, 0)
	return errs
}

// collectPtrRefs walks an ArgNode tree and collects all ptr references with their required interfaces.
func collectPtrRefs(node *ArgNode, assert Assert, assertRefs map[string]Assert) []ptrRef {
	if node == nil {
		return nil
	}
	var refs []ptrRef
	var walk func(*ArgNode, Assert, string)
	walk = func(n *ArgNode, a Assert, path string) {
		if n == nil {
			return
		}
		switch n.Type {
		case "ptr":
			if name, ok := n.Value.(string); ok && name != "" {
				refs = append(refs, ptrRef{target: name, impls: a.Impls, fieldPath: path})
			} else if m, ok := n.Value.(map[string]*ArgNode); ok {
				if kindNode := m["kind"]; kindNode != nil && kindNode.Type == "string" {
					kind := kindNode.ToString()
					// Check inline kind's return type against parent's required interfaces
					if len(a.Impls) > 0 {
						refs = append(refs, ptrRef{inlineKind: kind, impls: a.Impls, fieldPath: path})
					}
					spec := &ArgNode{Type: "null"}
					if len(m) > 1 {
						remaining := make(map[string]*ArgNode, len(m)-1)
						for k, v := range m {
							if k != "kind" {
								remaining[k] = v
							}
						}
						spec = &ArgNode{Type: "map", Value: remaining}
					}
					if sub, ok := assertRefs[kind]; ok {
						walk(spec, sub, path+"("+kind+")")
					}
				}
			}
		case "map":
			if m, ok := n.Value.(map[string]*ArgNode); ok {
				for k, v := range m {
					sub := Assert{}
					if s, ok := a.Sub[k]; ok {
						sub = s
					} else if s, ok := a.Sub["_"]; ok {
						sub = s
					}
					walk(v, sub, path+"."+k)
				}
			}
		case "list":
			if items, ok := n.Value.([]*ArgNode); ok {
				subAssert := a.Sub["_"]
				for i, item := range items {
					walk(item, subAssert, path+"["+fmt.Sprint(i)+"]")
				}
			}
		}
	}
	walk(node, assert, "")
	return refs
}

func (space *Space) Apply(root *ArgNode, reload bool, dry bool) error {
	srvs := root.MustGet("Services")
	if srvs == nil || srvs.Type != "map" {
		return fmt.Errorf("Services must be a map, got %s", srvs.Type)
	}

	var entries []serviceEntry
	for name, entry := range srvs.ToMap() {
		entryMap := entry.ToMap()
		kindNode, ok := entryMap["kind"]
		if !ok || kindNode == nil {
			return fmt.Errorf("service %q: missing kind", name)
		}
		kind := kindNode.ToString()
		delete(entryMap, "kind")

		// Remaining fields are the spec (flattened config format)
		var spec *ArgNode
		if len(entryMap) == 0 {
			spec = &ArgNode{Type: "null", Value: nil}
		} else {
			spec = &ArgNode{Type: "map", Value: entryMap}
		}

			ref, ok := space.Refs[kind]
			if !ok {
				return fmt.Errorf("service %q: kind not found: %s", name, kind)
			}
			assert, ok := space.AssertRefs[kind]
			if !ok {
				return fmt.Errorf("service %q: assert not found: %s", name, kind)
			}

			if err := AssertArg(spec, assert); err != nil {
				return fmt.Errorf("service %q (%s): assert failed: %w", name, kind, err)
			}

			deps := space.collectDeps(spec, assert)
			entries = append(entries, serviceEntry{
				name: name, kind: kind, spec: spec,
				ref: ref, assert: assert, deps: deps,
			})
	}

	// Build set of pre-populated service names
	prePopulated := map[string]bool{}
	for name := range space.Services {
		prePopulated[name] = true
	}

	// Topological sort
	order, err := topoSort(entries, prePopulated)
	if err != nil {
		return err
	}

	// Print topological order
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Topological Order")
	fmt.Fprintln(os.Stderr, "  ─────────────────")
	for i, idx := range order {
		e := entries[idx]
		arrow := "  │"
		if i == len(order)-1 {
			arrow = "  └"
		} else {
			arrow = "  ├"
		}
		deps := ""
		if len(e.deps) > 0 {
			seen := map[string]bool{}
			var unique []string
			for _, d := range e.deps {
				if !seen[d] {
					seen[d] = true
					unique = append(unique, d)
				}
			}
			deps = " ← " + strings.Join(unique, ", ")
		}
		fmt.Fprintf(os.Stderr, "%s %2d  %-20s %-30s%s\n", arrow, i, e.name, e.kind, deps)
	}
	fmt.Fprintln(os.Stderr, "")

	// Instantiate in dependency order
	reload_errors := []error{}
	for _, idx := range order {
		e := entries[idx]
		_time := time.Now()

		err := space.Deptr(e.spec, dry, e.assert, e.name)
		if err != nil {
			ret_err := fmt.Errorf("%s (%s): %w", e.name, e.kind, err)
			log.Error().Caller().Str("err", ret_err.Error()).Msg("failed to deptr")
			if !reload {
				return ret_err
			}
			reload_errors = append(reload_errors, ret_err)
			continue
		}

		var inst any
		if !dry {
			inst, err = safeInst(e.ref, e.spec)
		}

		if err != nil {
			ret_err := fmt.Errorf("%s (%s): %w", e.name, e.kind, err)
			log.Error().Caller().Str("err", ret_err.Error()).Msg("failed to instantiate")
			if !reload {
				return ret_err
			}
			reload_errors = append(reload_errors, ret_err)
			continue
		}

		if e.name != "" && e.name != "_" && inst != nil {
			space.Services[e.name] = inst
			space.ServiceKinds[e.name] = e.kind
		}

		log.Info().Str("kind", e.kind).Str("name", e.name).Dur("elapsed", time.Since(_time)).Msg("service applied")
	}

	if reload && len(reload_errors) > 0 {
		var errstr string
		for _, e := range reload_errors {
			errstr += e.Error() + "\n"
		}
		return fmt.Errorf("reload failed:\n%s", errstr)
	}

	return nil
}

func (space *Space) Call(ref string, spec *ArgNode) (any, error) {
	ref_func, ok := space.Refs[ref]
	if !ok {
		return nil, fmt.Errorf("kind not found: %s", ref)
	}

	spec_assert, ok := space.AssertRefs[ref]
	if !ok {
		return nil, fmt.Errorf("assert not found: %s", ref)
	}

	err := AssertArg(spec, spec_assert)
	if err != nil {
		return nil, fmt.Errorf("%s: assert failed: %w", ref, err)
	}

	err = space.Deptr(spec, false, spec_assert, "")

	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}

	inst, err := safeInst(ref_func, spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	return inst, nil
}

func AssertArg(node *ArgNode, assertions Assert) error {
	if node == nil {
		if assertions.Type == "null" || assertions.Type == "any" {
			return nil
		} else {
			return fmt.Errorf("required field is nil")
		}
	}
	if node.Type == "null" {
		if !assertions.Required {
			node.Type = assertions.Type
			// Copy map defaults to avoid mutating the Assert registry
			if m, ok := assertions.Default.(map[string]*ArgNode); ok {
				cp := make(map[string]*ArgNode, len(m))
				for k, v := range m {
					cp[k] = v
				}
				node.Value = cp
			} else {
				node.Value = assertions.Default
			}
		} else {
			return fmt.Errorf("required field is null")
		}
	} else {
		if assertions.Type != "any" {
			if err := IfCompatibleAndConvert(node, assertions); err != nil {
				return err
			}
		}
		// if assertions.Forced && assertions.Default != nil && assertions.Type != "url" {
		// 	if !reflect.DeepEqual(node.Value, assertions.Default) {
		// 		return fmt.Errorf("forced field not met requirements wanted: %v, got: %v", assertions.Default, node.Value)
		// 	}
		// }
	}

	switch assertions.Type {
	case "map":
		if node.Value == nil {
			node.Value = map[string]*ArgNode{}
		}

		if subnodes, ok := node.Value.(map[string]*ArgNode); ok {
			keys := map[string]struct{}{}
			for k := range subnodes {
				keys[k] = struct{}{}
			}

			for k, v := range assertions.Sub {
				subnode, ok := subnodes[k]
				if !ok {
					if v.Required {
						return fmt.Errorf("missing required key: %s", strconv.Quote(k))
					} else {
						if v.Default != nil {
							node := &ArgNode{
								Type:  v.Type,
								Value: v.Default,
							}
							AssertArg(node, v)
							subnodes[k] = node
						} else {
							continue
						}
					}
					continue
				}
				if err := AssertArg(subnode, v); err != nil {
					return fmt.Errorf("key %s: %w", strconv.Quote(k), err)
				}

				delete(keys, k)
			}

			if len(keys) > 0 {
				defaultassertion, ok := assertions.Sub["_"]
				if !ok {
					return fmt.Errorf("no default assertion provided. got unexpected keys: %v", keys)
				}
				for k := range keys {
					subnode := subnodes[k]
					if err := AssertArg(subnode, defaultassertion); err != nil {
						return fmt.Errorf("key %s: %w", strconv.Quote(k), err)
					}
				}
			}
			return nil
		}
	case "list":

		if node.Value == nil {
			node.Value = []*ArgNode{}
			return nil
		}

		realnodes, ok := node.Value.([]*ArgNode)
		if !ok {
			return fmt.Errorf("expected list, got %T", node.Value)
		}

		len_asserts := len(assertions.SubList)
		defaultassertion, hasdefault := assertions.Sub["_"]

		for i, subnode := range realnodes {
			if len_asserts > i {
				if err := AssertArg(subnode, assertions.SubList[i]); err != nil {
					return fmt.Errorf("index %d: %w", i, err)
				}
				continue
			}
			if !hasdefault {
				return fmt.Errorf("no default assertion provided for index %d", i)
			}
			if err := AssertArg(subnode, defaultassertion); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}
	case "url":
		if node.Value == nil {
			node.Value = []*ngnet.URL{}
			return nil
		}
		realnode, ok := node.Value.(*ngnet.URL)
		if !ok {
			return fmt.Errorf("expected url, got %T", node.Value)
		}

		if assertions.Default != nil {
			assertnode := assertions.Default.(*ngnet.URL)

			// if assertions.Forced && realnode.Interface != assertnode.Interface {
			// 	return fmt.Errorf("url interface mismatch: %s != %s", realnode.Interface, assertnode.Interface)
			// }

			if assertnode.Interface != "" {

				if realnode.Interface == "" {
					realnode.Interface = assertnode.Interface
				}
			}
			if assertnode.URL.Scheme != "" {
				// if assertions.Forced && realnode.URL.Scheme != assertnode.URL.Scheme {
				// 	return fmt.Errorf("url scheme mismatch: %s != %s", realnode.URL.Scheme, assertnode.URL.Scheme)
				// }
				if realnode.URL.Scheme == "" {
					realnode.URL.Scheme = assertnode.URL.Scheme
				}
			}
			if assertnode.URL.Host != "" {
				// if assertions.Forced && realnode.URL.Host != assertnode.URL.Host {
				// 	return fmt.Errorf("url host mismatch: %s != %s", realnode.URL.Host, assertnode.URL.Host)
				// }
				if realnode.URL.Host == "" {
					realnode.URL.Host = assertnode.URL.Host
				}
			}
			if assertnode.URL.Path != "" {
				// if assertions.Forced && realnode.URL.Path != assertnode.URL.Path {
				// 	return fmt.Errorf("url path mismatch: %s != %s", realnode.URL.Path, assertnode.URL.Path)
				// }
				if realnode.URL.Path == "" {
					realnode.URL.Path = assertnode.URL.Path
				}
			}
			if assertnode.URL.RawQuery != "" {
				// if assertions.Forced && realnode.URL.RawQuery != assertnode.URL.RawQuery {
				// 	return fmt.Errorf("url query mismatch: %s != %s", realnode.URL.RawQuery, assertnode.URL.RawQuery)
				// }
				if realnode.URL.RawQuery == "" {
					realnode.URL.RawQuery = assertnode.URL.RawQuery
				}
			}
			if assertnode.URL.RawFragment != "" {
				// if assertions.Forced && realnode.URL.RawFragment != assertnode.URL.RawFragment {
				// 	return fmt.Errorf("url fragment mismatch: %s != %s", realnode.URL.RawFragment, assertnode.URL.RawFragment)
				// }
				if realnode.URL.RawFragment == "" {
					realnode.URL.RawFragment = assertnode.URL.RawFragment
				}
			}
		}
	}

	return nil
}

func IfCompatibleAndConvert(node *ArgNode, assertions Assert) error {

	if node.Type == assertions.Type {
		return nil
	}

	incompatible := fmt.Errorf("type incompatible: %s !-> %s (%v)", node.Type, assertions.Type, node.Value)

	switch assertions.Type {
	case "list":
		if node.Type != "list" &&
			len(assertions.SubList) == 1 &&
			len(assertions.Sub) == 0 &&
			assertions.SubList[0].Type == "ptr" {
			clone := &ArgNode{
				Type:  node.Type,
				Value: node.Value,
			}
			node.Type = "list"
			node.Value = []*ArgNode{clone}
			return nil
		}
	case "ptr":
		if node.Type == "string" {
			node.Type = "ptr"
			return nil
		}
		if node.Type == "map" {
			if m, ok := node.Value.(map[string]*ArgNode); ok {
				if _, ok := m["kind"]; ok {
					node.Type = "ptr"
					return nil
				}
			}
		}
	case "duration":
		if node.Type == "string" {
			dur, err := time.ParseDuration(node.Value.(string))
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			node.Type = "duration"
			node.Value = dur
			return nil
		}
	case "url": // iface%scheme://host:port/path?query#fragment
		if node.Type == "string" {
			str := node.Value.(string)
			idx_percent := strings.Index(str, "%")
			idx_colon := strings.Index(str, ":")
			iface_ptr := ""

			if idx_percent != -1 {
				if idx_percent < idx_colon {
					iface_ptr = str[:idx_percent]
					str = str[idx_percent+1:]
				}
			}

			_url, err := url.Parse(str)
			if err != nil {
				return fmt.Errorf("invalid url: %w", err)
			}

			node.Type = "url"
			node.Value = &ngnet.URL{
				Interface: iface_ptr,
				URL:       *_url,
			}
			return nil
		}
	case "hostname": // should be a valid hostname, use regexp to check
		if node.Type == "string" {
			re := regexp2.MustCompile(`^[A-Za-z0-9.*-]+(?::\d{1,5})?$`, regexp2.RE2)
			if ok, _ := re.MatchString(node.Value.(string)); ok {
				node.Type = "hostname"
				return nil
			}
			return fmt.Errorf("invalid hostname: %q", node.Value)
		}
	case "regexp":
		if node.Type == "string" {
			pattern := node.Value.(string)
			exp, err := regexp2.Compile(pattern, regexp2.RE2)
			if err != nil {
				return fmt.Errorf("invalid regexp: %w", err)
			}
			node.Type = "regexp"
			node.Value = exp
			return nil
		}
	case "expr":
		if node.Type == "string" {
			if assertions.ExprCheck != nil {
				if err := assertions.ExprCheck(node.Value.(string)); err != nil {
					return fmt.Errorf("expr compile: %w", err)
				}
			}
			node.Type = "expr"
			return nil
		}
	}

	return incompatible
}

func validateInterfaces(a Assert, v any) error {
	if v == nil {
		if a.AllowNil {
			return nil
		}
		return fmt.Errorf("nil does not implement required interfaces")
	}

	rt := reflect.TypeOf(v)

	rv := reflect.ValueOf(v)

	if a.Struct {
		for _, t := range a.Impls {
			if rt == t || rt == reflect.PointerTo(t) {
				return nil
			}
		}
		return fmt.Errorf("type %v does not match required struct types", rt)
	}

	switch rv.Kind() {
	case reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if rv.IsNil() && !a.AllowNil {
			return fmt.Errorf("value is typed-nil for %v", rt)
		}
	}

	for _, it := range a.Impls {
		if it.Kind() != reflect.Interface {
			return fmt.Errorf("GoImplements must be interface types, got %v", it)
		}
		if !rt.Implements(it) {
			return fmt.Errorf("type %v does not implement %v", rt, it)
		}
	}
	return nil
}
