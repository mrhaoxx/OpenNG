package ng

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog/log"
)

type Space struct {
	Services     map[string]any
	AssertRefs   map[string]Assert
	Refs         map[string]Inst
	ServiceKinds map[string]string
}

func (space *Space) Deptr(root *ArgNode, validate bool, _assert Assert) error {
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
				} else {
					return fmt.Errorf("ptr not found: %s", v)
				}
			case map[string]*ArgNode:
				if validate {
					node.Value = nil
					break
				}
				inst, err := space.instantiateAnon(v, validate)
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
				inst, err := space.instantiateAnon(mm, validate)
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

func (space *Space) instantiateAnon(m map[string]*ArgNode, validate bool) (any, error) {
	var kind string
	if k, ok := m["kind"]; ok && k != nil {
		if k.Type != "string" {
			return nil, fmt.Errorf("anonymous object: kind must be string")
		}
		kind = k.ToString()
	} else {
		return nil, fmt.Errorf("anonymous object missing kind")
	}

	spec := &ArgNode{Type: "null", Value: nil}
	if s, ok := m["spec"]; ok && s != nil {
		spec = s
	}

	specAssert, ok := space.AssertRefs[kind]
	if !ok {
		return nil, fmt.Errorf("assert not found: %s", kind)
	}
	if err := AssertArg(spec, specAssert); err != nil {
		return nil, fmt.Errorf("%s: assert failed: %w", kind, err)
	}

	if err := space.Deptr(spec, validate, specAssert); err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}

	ref, ok := space.Refs[kind]
	if !ok {
		return nil, fmt.Errorf("kind not found: %s", kind)
	}

	if validate {
		defer func() {
			if r := recover(); r != nil {
			}
		}()
	}

	inst, err := ref(spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	return inst, nil
}

func (space *Space) Validate(root *ArgNode) []error {
	errors := []error{}

	srvs := root.MustGet("Services")

	for i, _srv := range srvs.Value.([]*ArgNode) {

		_ref := _srv.MustGet("kind").ToString()
		to := _srv.MustGet("name").ToString()
		spec := _srv.MustGet("spec")
		recv := ""
		if tnode, err := _srv.Get("recv"); err == nil && tnode != nil {
			recv = tnode.ToString()
		}

		resolvedKind, err := space.resolveKindReference(_ref, recv, spec)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err))
			continue
		}

		for _, c := range to {
			if (c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '_' || c == '-' {
				continue
			} else {
				ret_err := fmt.Errorf("%s: invalid service name: %s", fmt.Sprintf("[%d] ", i)+_ref, to)

				errors = append(errors, ret_err)
				break
			}
		}

		normalizeFuncSpec(resolvedKind, spec)

		spec_assert, ok := space.AssertRefs[resolvedKind]
		if !ok {
			errors = append(errors, fmt.Errorf("%s assert not found: %s", fmt.Sprintf("[%d]", i), _ref))
			continue
		}

		err = AssertArg(spec, spec_assert)

		if err != nil {
			errors = append(errors, fmt.Errorf("%s assert failed: %s %w", fmt.Sprintf("[%d]", i), _ref, err))
			continue
		}

		err = space.Deptr(spec, true, spec_assert)

		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err))
			continue
		}

		if to != "" && to != "_" {
			space.Services[to] = true
			if space.ServiceKinds == nil {
				space.ServiceKinds = map[string]string{}
			}
			space.ServiceKinds[to] = resolvedKind
		}

	}

	return errors
}

func (space *Space) Apply(root *ArgNode, reload bool) error {
	reload_errors := []error{}
	srvs := root.MustGet("Services")

	for i, _srv := range srvs.Value.([]*ArgNode) {
		kind := _srv.MustGet("kind").ToString()
		_time := time.Now()

		_ref := kind
		to := _srv.MustGet("name").ToString()

		// to should only contain alphanumeric, _, -
		for _, c := range to {
			if (c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '_' || c == '-' {
				continue
			} else {
				ret_err := fmt.Errorf("%s: invalid service name: %s", fmt.Sprintf("[%d] ", i)+_ref, to)

				if !reload {
					return ret_err
				} else {
					reload_errors = append(reload_errors, ret_err)
					break
				}
			}
		}

		spec := _srv.MustGet("spec")
		recv := ""
		if tnode, err := _srv.Get("recv"); err == nil && tnode != nil {
			recv = tnode.ToString()
		}

		resolvedKind, err := space.resolveKindReference(_ref, recv, spec)
		if err != nil {
			ret_err := fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)
			if !reload {
				return ret_err
			}
			reload_errors = append(reload_errors, ret_err)
			continue
		}

		ref, ok := space.Refs[resolvedKind]
		if !ok {
			return fmt.Errorf("kind not found: %s", fmt.Sprintf("[%d] ", i)+_ref)
		}

		normalizeFuncSpec(resolvedKind, spec)

		spec_assert, ok := space.AssertRefs[resolvedKind]
		if !ok {
			return fmt.Errorf("assert not found: %s", fmt.Sprintf("[%d] ", i)+_ref)
		}

		err = AssertArg(spec, spec_assert)
		if err != nil {
			return fmt.Errorf("%s: assert failed: %w", fmt.Sprintf("[%d] ", i)+_ref, err)
		}

		err = space.Deptr(spec, false, spec_assert)

		if err != nil {
			ret_err := fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)

			log.Error().Caller().Str("err", ret_err.Error()).Msg("failed to deptr")

			if !reload {
				return ret_err
			} else {
				reload_errors = append(reload_errors, ret_err)
				continue
			}
		}

		inst, err := ref(spec)

		if err != nil {
			ret_err := fmt.Errorf("%s: %w", fmt.Sprintf("[%d] ", i)+_ref, err)

			log.Error().Caller().Str("err", ret_err.Error()).Msg("failed to call ref")

			if !reload {
				return ret_err
			} else {
				reload_errors = append(reload_errors, ret_err)
				continue
			}
		}

		space.Services[to] = inst
		if to != "" && to != "_" {
			if space.ServiceKinds == nil {
				space.ServiceKinds = map[string]string{}
			}
			space.ServiceKinds[to] = resolvedKind
		}

		// used_time := fmt.Sprintf("[%4d][%10s]", i, time.Since(_time).String())

		log.Info().Str("kind", _ref).Str("name", to).Dur("elapsed", time.Since(_time)).Int("index", i).Msg("service applied")

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

func (space *Space) resolveKindReference(kind, recv string, spec *ArgNode) (string, error) {
	if recv != "" {
		return space.resolveMemberFunction(recv, kind, spec)
	}

	if !strings.Contains(kind, ".") {
		return kind, nil
	}

	parts := strings.SplitN(kind, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid member function reference: %s", kind)
	}

	return space.resolveMemberFunction(parts[0], parts[1], spec)
}

func (space *Space) resolveMemberFunction(targetName, memberName string, spec *ArgNode) (string, error) {
	if targetName == "" {
		return "", fmt.Errorf("member function call missing target")
	}
	if memberName == "" {
		return "", fmt.Errorf("member function call missing method name")
	}

	baseKind, ok := space.ServiceKinds[targetName]
	if !ok {
		return "", fmt.Errorf("service not found for member call: %s", targetName)
	}

	methods, ok := member_func_registry[baseKind]
	if !ok || len(methods) == 0 {
		return "", fmt.Errorf("service %s (%s) has no member functions", targetName, baseKind)
	}

	member, exists := methods[memberName]
	if !exists {
		for key, fn := range methods {
			if strings.EqualFold(key, memberName) {
				member = fn
				exists = true
				break
			}
		}
	}
	if !exists {
		return "", fmt.Errorf("member function %s not found for %s (%s)", memberName, targetName, baseKind)
	}

	normalizeFuncSpec(member.FullName, spec)

	if err := ensureMemberSpecHasPtr(spec, targetName); err != nil {
		return "", err
	}

	return member.FullName, nil
}

func ensureMemberSpecHasPtr(spec *ArgNode, target string) error {
	if spec == nil {
		return fmt.Errorf("spec missing for member call on %s", target)
	}
	if spec.Type == "null" {
		spec.Type = "map"
		spec.Value = map[string]*ArgNode{}
	}
	if spec.Type != "map" {
		return fmt.Errorf("member function call expects structured spec, got %s", spec.Type)
	}
	if spec.Value == nil {
		spec.Value = map[string]*ArgNode{}
	}

	subnodes, ok := spec.Value.(map[string]*ArgNode)
	if !ok {
		return fmt.Errorf("member function call spec is invalid")
	}

	subnodes["ptr"] = &ArgNode{
		Type:  "ptr",
		Value: target,
	}
	return nil
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
			node.Value = assertions.Default
		} else {
			return fmt.Errorf("required field is null")
		}
	} else {
		if assertions.Type != "any" && !IfCompatibleAndConvert(node, assertions) {
			return fmt.Errorf("type incompatible: %s !-> %s (%v)", node.Type, assertions.Type, node.Value)
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
		defaultassertion, ok := assertions.Sub["_"]
		if !ok {
			return fmt.Errorf("missing default assertion")
		}

		if node.Value == nil {
			node.Value = []*ArgNode{}
			return nil
		}

		realnodes, ok := node.Value.([]*ArgNode)
		if !ok {
			return fmt.Errorf("expected list, got %T", node.Value)
		}
		for i, subnode := range realnodes {
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

func IfCompatibleAndConvert(node *ArgNode, assertions Assert) bool {

	if node.Type == assertions.Type {
		return true
	}

	switch assertions.Type {
	case "ptr":
		if node.Type == "string" {
			node.Type = "ptr"
			return true
		}
		if node.Type == "map" {
			if m, ok := node.Value.(map[string]*ArgNode); ok {
				if _, ok := m["kind"]; ok {
					node.Type = "ptr"
					return true
				}
			}
		}
	case "duration":
		if node.Type == "string" {
			if dur, err := time.ParseDuration(node.Value.(string)); err == nil {
				node.Type = "duration"
				node.Value = dur
				return true
			}
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
				return false
			}

			node.Type = "url"
			node.Value = &ngnet.URL{
				Interface: iface_ptr,
				URL:       *_url,
			}
			return true
		}
	case "hostname": // should be a valid hostname, use regexp to check
		if node.Type == "string" {
			re := regexp2.MustCompile(`^[A-Za-z0-9.*-]+(?::\d{1,5})?$`, regexp2.RE2)
			if ok, _ := re.MatchString(node.Value.(string)); ok {
				node.Type = "hostname"
				return true
			}
		}
	case "regexp":
		if node.Type == "string" {
			pattern := node.Value.(string)
			exp, err := regexp2.Compile(pattern, regexp2.RE2)
			if err != nil {
				return false
			}
			node.Type = "regexp"
			node.Value = exp
			return true
		}
	}

	return false
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
