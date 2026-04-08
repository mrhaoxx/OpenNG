package ng

import (
	_ "embed"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngdns"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

//go:embed modules/admin/html/public/NetGATE.svg
var logo_svg []byte

func Logo() []byte {
	return logo_svg
}

const (
	ServerSign = "OpenNG"
)

var args_asserts = map[string]Assert{}
var ret_asserts = map[string]Assert{}

// var member_func_registry = map[string]map[string]MemberFunction{}

var refs = map[string]Inst{}
var asserterInterfaceType = reflect.TypeFor[Asserter]()
var unmarshalerInterfaceType = reflect.TypeFor[Unmarshaler]()
var errorType = reflect.TypeOf((*error)(nil)).Elem()

func Register(name string, args Assert, ret Assert, inst Inst) {
	refs[name] = inst
	args_asserts[name] = args
	ret_asserts[name] = ret
}

func Registry() map[string]Inst {
	return refs
}

func AssertionsRegistry() map[string]Assert {
	return args_asserts
}

func ReturnAssertionsRegistry() map[string]Assert {
	return ret_asserts
}

// func MemberFunctionRegistry() map[string]map[string]MemberFunction {
// 	return member_func_registry
// }

type Inst func(*ArgNode) (any, error)

type AssertMap map[string]Assert
type AssertList []Assert

type Assert struct {
	Type     string
	Required bool
	Forced   bool

	Sub      AssertMap
	SubList  AssertList
	SubOrder []string // field order for struct-derived maps

	Default any

	Desc string

	Struct   bool
	Impls    []reflect.Type
	AllowNil bool

	ExprEnv   any              // for type "expr": environment tree for autocomplete
	ExprCheck func(string) error // for type "expr": compile-check an expression string
}

type MemberFunction struct {
	FullName string
	Args     Assert
	Ret      Assert
}

func TypeOf[T any]() reflect.Type {
	var z *T
	return reflect.TypeOf(z).Elem()
}

type ArgNode struct {
	Type  string
	Value any
}

// DeepCopy returns a deep clone of the ArgNode tree.
func (node *ArgNode) DeepCopy() *ArgNode {
	if node == nil {
		return nil
	}
	cp := &ArgNode{Type: node.Type}
	switch v := node.Value.(type) {
	case map[string]*ArgNode:
		m := make(map[string]*ArgNode, len(v))
		for k, child := range v {
			m[k] = child.DeepCopy()
		}
		cp.Value = m
	case []*ArgNode:
		s := make([]*ArgNode, len(v))
		for i, child := range v {
			s[i] = child.DeepCopy()
		}
		cp.Value = s
	default:
		cp.Value = node.Value // scalars are immutable
	}
	return cp
}

func (node *ArgNode) MustGet(path string) *ArgNode {
	v, _ := node.Get(path)
	return v
}

func (node *ArgNode) ToString() string {
	if node == nil {
		return ""
	}

	return node.Value.(string)
}

func (node *ArgNode) ToInt() int {
	if node == nil {
		return 0
	}
	if node.Type != "int" {
		return 0
	}
	return node.Value.(int)
}

func (node *ArgNode) ToBool() bool {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "bool" {
		return false
	}
	return node.Value.(bool)
}

func (node *ArgNode) ToList() []*ArgNode {
	if node == nil {
		return nil
	}

	if node.Type != "list" {
		return nil
	}
	return node.Value.([]*ArgNode)
}

func (node *ArgNode) ToMap() map[string]*ArgNode {
	if node == nil {
		panic("nil node")
	}

	if node.Type != "map" {
		return nil
	}
	return node.Value.(map[string]*ArgNode)
}

func (node *ArgNode) ToDuration() time.Duration {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "duration" {
		return 0
	}

	return node.Value.(time.Duration)
}

func (node *ArgNode) ToURL() *ngnet.URL {
	if node == nil {
		panic("nil node")
	}
	if node.Type != "url" {
		return nil
	}

	return node.Value.(*ngnet.URL)
}

func (node *ArgNode) ToRegexp() *regexp2.Regexp {
	if node == nil {
		panic("nil node")
	}

	switch node.Type {
	case "hostname":
		return regexp2.MustCompile(ngdns.Dnsname2Regexp(node.Value.(string)), regexp2.RE2)
	case "regexp":
		return node.Value.(*regexp2.Regexp)
	default:
		return nil
	}
}

func (node *ArgNode) ToAny() any {
	if node == nil {
		return nil
	}
	switch node.Type {
	case "map":
		ret := map[string]any{}
		for k, v := range node.Value.(map[string]*ArgNode) {
			ret[k] = v.ToAny()
		}
		return ret

	case "list":
		ret := make([]any, len(node.ToList()))
		for i, v := range node.ToList() {
			ret[i] = v.ToAny()
		}
		return ret
	default:
		return node.Value
	}
}

func (node *ArgNode) ToStringList() []string {
	if node == nil {
		return nil
	}

	if node.Type != "list" {
		return nil
	}
	var ret []string
	for _, v := range node.ToList() {
		ret = append(ret, v.ToString())
	}
	return ret
}

func (node *ArgNode) ToGroupRegexp() groupexp.GroupRegexp {
	if node == nil {
		return nil
	}

	if node.Type != "list" {
		return nil
	}

	var ret groupexp.GroupRegexp
	for _, v := range node.ToList() {
		if v.Value == nil {
			continue
		}
		ret = append(ret, v.ToRegexp())
	}
	return ret
}

func (m *ArgNode) FromAny(raw any) error {
	switch raw := raw.(type) {
	case nil:
		m.Type = "null"
		m.Value = nil
		return nil
	case string:
		switch {
		case strings.HasPrefix(raw, "$dref{"):
			{
				if strings.HasSuffix(raw, "...") {
					m.Type = "dref..."
					m.Value = raw[len("$dref{") : len(raw)-4]
					return nil
				}
				m.Type = "dref"
				m.Value = raw[len("$dref{") : len(raw)-1]
				return nil
			}
		default:
			m.Type = "string"
			m.Value = raw
			return nil
		}
	case int:
		m.Type = "int"
		m.Value = raw
		return nil
	case float64:
		m.Type = "float"
		m.Value = raw
		return nil
	case bool:
		m.Type = "bool"
		m.Value = raw
		return nil
	case map[string]any:
		subnodes := make(map[string]*ArgNode)
		for k, v := range raw {
			subnode := &ArgNode{}
			err := subnode.FromAny(v)
			if err != nil {
				return err
			}
			subnodes[k] = subnode
		}
		m.Type = "map"
		m.Value = subnodes
		return nil
	case []interface{}:
		subnodes := make([]*ArgNode, len(raw))
		for i, v := range raw {
			subnode := &ArgNode{}
			err := subnode.FromAny(v)
			if err != nil {
				return err
			}
			subnodes[i] = subnode
		}
		m.Type = "list"
		m.Value = subnodes
		return nil
	default:
		return fmt.Errorf("unsupported type: %T", raw)
	}
}

func (node *ArgNode) Get(path string) (*ArgNode, error) {
	if path == "" {
		return node, nil
	}

	if node == nil {
		return nil, fmt.Errorf("path not found")
	}

	switch node.Type {
	case "map":
		access := strings.Split(path, ".")

		rh := access[0]
		if strings.HasSuffix(access[0], "]") {
			rh = rh[:strings.LastIndex(access[0], "[")]
			access[0] = access[0][len(rh):]
		} else {
			access = access[1:]
		}

		v, ok := node.ToMap()[rh]
		if !ok {
			return nil, fmt.Errorf("path not found")
		}
		return v.Get(strings.Join(access, "."))
	case "list":
		if strings.HasPrefix(path, "[") {

			var index int
			fmt.Sscanf(path, "[%d]", &index)
			inds := path[len(fmt.Sprintf("[%d]", index)):]
			if inds == "" {
				return node.ToList()[index], nil
			} else if inds[0] == '.' {
				return node.ToList()[index].Get(inds[1:])
			}
			return nil, fmt.Errorf("invalid path")
		} else {
			for _, v := range node.ToList() {
				name, err := v.Get("name")
				if err != nil || name.Type != "string" {
					continue
				}
				if strings.HasPrefix(path, name.Value.(string)) {
					inds := path[len(name.Value.(string)):]
					if inds == "" {
						return v, nil
					} else if inds[0] == '.' {
						return v.Get(inds[1:])
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("path not found")
}

func (node *ArgNode) Unmarshal(target any) error {
	if target == nil {
		return fmt.Errorf("target cannot be nil")
	}

	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	}

	return node.unmarshalValue(target)
}

func (node *ArgNode) unmarshalValue(dst any) error {
	var target reflect.Value

	switch v := dst.(type) {
	case reflect.Value:
		target = v
	default:
		rv := reflect.ValueOf(dst)
		if rv.Kind() != reflect.Pointer || rv.IsNil() {
			return fmt.Errorf("target must be a non-nil pointer or reflect.Value, got %T", dst)
		}
		target = rv.Elem()
	}

	return node.assignValue(target)
}

func (node *ArgNode) assignValue(dst reflect.Value) error {
	if !dst.CanSet() {
		return fmt.Errorf("cannot set value of type %s", dst.Type())
	}

	if node == nil || node.Type == "null" {
		dst.SetZero()
		return nil
	}

	if handled, err := node.tryCustomUnmarshal(dst); handled {
		return err
	}

	// builtin types
	if dst.Type() == reflect.TypeFor[ngnet.URL]() {
		urlValue, ok := node.Value.(*ngnet.URL)
		if !ok {
			return fmt.Errorf("expected ngnet.URL value, got %T", node.Value)
		}
		dst.Set(reflect.ValueOf(*urlValue))
		return nil
	}

	if dst.Kind() == reflect.Interface {
		dst.Set(reflect.ValueOf(node.interfaceValue()))
		return nil
	}

	if dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		if reflect.TypeOf(node.Value).AssignableTo(dst.Type()) {
			dst.Set(reflect.ValueOf(node.Value))
		} else {
			return node.assignValue(dst.Elem())
		}
	}

	switch dst.Kind() {
	case reflect.Struct:
		return node.unmarshalStruct(dst)
	case reflect.Map:
		return node.unmarshalMap(dst)
	case reflect.Slice:
		return node.unmarshalSlice(dst)
	case reflect.Array:
		return node.unmarshalArray(dst)
	}

	val := reflect.ValueOf(node.Value)
	if !val.IsValid() {
		dst.SetZero()
		return nil
	}
	if val.Type().AssignableTo(dst.Type()) {
		dst.Set(val)
		return nil
	}
	if val.Type().ConvertibleTo(dst.Type()) {
		dst.Set(val.Convert(dst.Type()))
		return nil
	}

	return fmt.Errorf("cannot assign %s to %s", val.Type(), dst.Type())
}

func (node *ArgNode) tryCustomUnmarshal(dst reflect.Value) (bool, error) {
	if !dst.IsValid() {
		return false, nil
	}

	if dst.Kind() == reflect.Pointer && dst.Type().Implements(unmarshalerInterfaceType) {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return true, dst.Interface().(Unmarshaler).UnmarshalArgNode(node)
	}

	if dst.CanInterface() && dst.Type().Implements(unmarshalerInterfaceType) {
		return true, dst.Interface().(Unmarshaler).UnmarshalArgNode(node)
	}

	if dst.CanAddr() {
		addr := dst.Addr()
		if addr.Type().Implements(unmarshalerInterfaceType) {
			return true, addr.Interface().(Unmarshaler).UnmarshalArgNode(node)
		}
	}

	if dst.CanSet() && dst.Kind() != reflect.Pointer {
		ptrType := reflect.PointerTo(dst.Type())
		if ptrType.Implements(unmarshalerInterfaceType) {
			temp := reflect.New(dst.Type())
			if err := temp.Interface().(Unmarshaler).UnmarshalArgNode(node); err != nil {
				return true, err
			}
			dst.Set(temp.Elem())
			return true, nil
		}
	}

	return false, nil
}

func (node *ArgNode) unmarshalStruct(dst reflect.Value) error {
	if node.Type != "map" {
		return fmt.Errorf("expected map for struct %s, got %s", dst.Type(), node.Type)
	}

	fields := dst.NumField()
	for i := 0; i < fields; i++ {
		fieldInfo := dst.Type().Field(i)
		if !fieldInfo.IsExported() {
			continue
		}

		ngTag := parseNgTag(fieldInfo.Tag.Get("ng"), fieldInfo.Name)
		if ngTag.skip {
			continue
		}

		fieldValue := dst.Field(i)

		if fieldInfo.Anonymous && fieldInfo.Tag.Get("ng") == "" {
			if err := node.unmarshalValue(fieldValue); err != nil {
				return err
			}
			continue
		}

		key := ngTag.key

		subnode, ok := node.ToMap()[key]
		if !ok || subnode == nil {
			continue
		}

		if err := subnode.unmarshalValue(fieldValue); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}

	return nil
}

func (node *ArgNode) unmarshalMap(dst reflect.Value) error {
	if node.Type != "map" {
		return fmt.Errorf("expected map for %s, got %s", dst.Type(), node.Type)
	}

	if dst.IsNil() {
		dst.Set(reflect.MakeMap(dst.Type()))
	}

	for k, v := range node.ToMap() {
		keyVal := reflect.ValueOf(k)
		keyType := dst.Type().Key()

		if !keyVal.Type().AssignableTo(keyType) {
			if keyVal.Type().ConvertibleTo(keyType) {
				keyVal = keyVal.Convert(keyType)
			} else {
				return fmt.Errorf("cannot convert map key %s to %s", keyVal.Type(), keyType)
			}
		}

		elem := reflect.New(dst.Type().Elem()).Elem()
		if v != nil {
			if err := v.unmarshalValue(elem); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		} else {
			elem.SetZero()
		}
		dst.SetMapIndex(keyVal, elem)
	}

	return nil
}

func (node *ArgNode) unmarshalSlice(dst reflect.Value) error {
	if node.Type != "list" {
		return fmt.Errorf("expected list for %s, got %s", dst.Type(), node.Type)
	}

	list := node.ToList()
	slice := reflect.MakeSlice(dst.Type(), len(list), len(list))
	for i, v := range list {
		if v == nil {
			slice.Index(i).SetZero()
			continue
		}
		if err := v.unmarshalValue(slice.Index(i)); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	dst.Set(slice)
	return nil
}

func (node *ArgNode) unmarshalArray(dst reflect.Value) error {
	if node.Type != "list" {
		return fmt.Errorf("expected list for %s, got %s", dst.Type(), node.Type)
	}

	list := node.ToList()
	if len(list) != dst.Len() {
		return fmt.Errorf("array length mismatch: have %d want %d", len(list), dst.Len())
	}
	for i, v := range list {
		if v == nil {
			dst.Index(i).SetZero()
			continue
		}
		if err := v.unmarshalValue(dst.Index(i)); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

func (node *ArgNode) interfaceValue() any {
	if node == nil {
		return nil
	}

	switch node.Type {
	case "map", "list":
		return node.ToAny()
	case "null":
		return nil
	default:
		return node.Value
	}
}

func ParseStruct(refType reflect.Type) (Assert, error) {
	// Check custom Asserter first for any type (slice, struct, etc.)
	if assert, ok := tryCustomAsserter(refType); ok {
		return assert, nil
	}

	switch refType.Kind() {
	case reflect.Array, reflect.Slice:
		elemType := refType.Elem()
		subAssert, err := ParseStruct(elemType)
		if err != nil {
			return Assert{}, err
		}
		return Assert{
			Type: "list",
			Sub: AssertMap{
				"_": subAssert,
			},
		}, nil
	case reflect.Struct:
		// check builtin types
		if refType == reflect.TypeFor[ngnet.URL]() {
			return Assert{
				Type: "url",
			}, nil
		}

		sub := AssertMap{}
		var order []string
		numFields := refType.NumField()
		for i := 0; i < numFields; i++ {
			field := refType.Field(i)
			if !field.IsExported() {
				continue
			}

			tag := parseNgTag(field.Tag.Get("ng"), field.Name)
			if tag.skip {
				continue
			}

			fieldAssert, err := ParseStruct(field.Type)
			if err != nil {
				return Assert{}, err
			}

			if notype := field.Tag.Get("type"); notype != "" {
				fieldAssert.Type = notype
			}
			if desc := field.Tag.Get("desc"); desc != "" {
				fieldAssert.Desc = desc
			}
			if tag.required {
				fieldAssert.Required = true
			}
			if tag.allowNil {
				fieldAssert.AllowNil = true
			}
			if defTag := field.Tag.Get("default"); defTag != "" {
				if d := parseDefaultTag(defTag, fieldAssert.Type); d != nil {
					fieldAssert.Default = d
				}
			}

			sub[tag.key] = fieldAssert
			order = append(order, tag.key)
		}
		return Assert{
			Type:     "map",
			Sub:      sub,
			SubOrder: order,
			Default:  map[string]*ArgNode{},
		}, nil
	case reflect.Ptr:
		return Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				refType,
			},
			Struct: true,
		}, nil
	case reflect.Map:
		return Assert{
			Type: "map",
			Sub: AssertMap{
				"_": func() Assert {
					subAssert, _ := ParseStruct(refType.Elem())
					return subAssert
				}(),
			},
		}, nil
	case reflect.Interface:
		// check if it is any
		if refType.NumMethod() == 0 {
			return Assert{
				Type: "any",
			}, nil
		}

		return Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				refType,
			},
		}, nil
	case reflect.String:
		return Assert{
			Type: "string",
		}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Assert{
			Type: "int",
		}, nil
	case reflect.Bool:
		return Assert{
			Type: "bool",
		}, nil
	case reflect.Float32, reflect.Float64:
		return Assert{
			Type: "float",
		}, nil
	default:
		if assert, ok := tryCustomAsserter(refType); ok {
			return assert, nil
		}
		// return Assert{}, fmt.Errorf("unsupported type: %s", refType)
		return Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				refType,
			},
			Struct: true,
		}, nil
	}
}

func tryCustomAsserter(refType reflect.Type) (Assert, bool) {
	if refType == nil {
		return Assert{}, false
	}

	if refType.Implements(asserterInterfaceType) {
		in := reflect.New(refType).Interface()
		return in.(Asserter).Assert(), true
	}

	if refType.Kind() != reflect.Pointer {
		ptrType := reflect.PointerTo(refType)
		if ptrType.Implements(asserterInterfaceType) {
			in := reflect.New(refType).Interface()
			return in.(Asserter).Assert(), true
		}
	}

	return Assert{}, false
}

// --- ng tag and default helpers for ParseStruct ---

type ngTagOpts struct {
	key      string
	skip     bool
	required bool
	allowNil bool
}

func parseNgTag(raw string, fieldName string) ngTagOpts {
	if raw == "-" {
		return ngTagOpts{skip: true}
	}
	opts := ngTagOpts{key: fieldName}
	if raw == "" {
		return opts
	}
	parts := strings.Split(raw, ",")
	if parts[0] != "" {
		opts.key = parts[0]
	}
	for _, p := range parts[1:] {
		switch strings.TrimSpace(p) {
		case "required":
			opts.required = true
		case "allownil":
			opts.allowNil = true
		}
	}
	return opts
}

// parseDefaultTag converts a string tag value to a typed default for the given Assert type.
func parseDefaultTag(raw string, assertType string) any {
	switch assertType {
	case "string":
		return raw
	case "int":
		if n, err := strconv.Atoi(raw); err == nil {
			return n
		}
	case "bool":
		if b, err := strconv.ParseBool(raw); err == nil {
			return b
		}
	case "float":
		if f, err := strconv.ParseFloat(raw, 64); err == nil {
			return f
		}
	case "duration":
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	case "list":
		// Support [item1,item2,...] syntax
		s := strings.TrimSpace(raw)
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			inner := strings.TrimSpace(s[1 : len(s)-1])
			if inner == "" {
				return []*ArgNode{}
			}
			parts := strings.Split(inner, ",")
			nodes := make([]*ArgNode, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					nodes = append(nodes, &ArgNode{Type: "string", Value: p})
				}
			}
			return nodes
		}
	case "ptr":
		return raw
	case "url":
		str := raw
		iface := ""
		if idx := strings.Index(str, "%"); idx != -1 {
			if cidx := strings.Index(str, ":"); cidx != -1 && idx < cidx {
				iface = str[:idx]
				str = str[idx+1:]
			}
		}
		u, err := url.Parse(str)
		if err != nil {
			return nil
		}
		return &ngnet.URL{Interface: iface, URL: *u}
	}
	return nil
}

func RegisterFunc(name string, fn any) error {
	fnValue := reflect.ValueOf(fn)
	if !fnValue.IsValid() || fnValue.Kind() != reflect.Func {
		return fmt.Errorf("RegisterFunc expects a function for %s", name)
	}

	fnType := fnValue.Type()
	numOut := fnType.NumOut()
	if numOut == 0 {
		return fmt.Errorf("%s: function must return error", name)
	}
	if fnType.Out(numOut-1) != errorType {
		return fmt.Errorf("%s: last return value must be error", name)
	}

	var retAssert Assert
	var err error

	argsAssert, listMode, err := buildFuncArgsAssert(fnType)
	if err != nil {
		return err
	}

	retAssert, err = _retAssert(fnType)
	if err != nil {
		return err
	}

	Register(name,
		argsAssert, retAssert, func(arg *ArgNode) (any, error) {
			callArgs, err := _specAssert(fnType, arg, listMode)
			if err != nil {
				return nil, err
			}
			results := fnValue.Call(callArgs)
			errVal, _ := results[numOut-1].Interface().(error)
			if errVal != nil {
				return nil, errVal
			}
			if numOut == 2 {
				return results[0].Interface(), nil
			}
			return nil, nil
		})

	if fnType.NumOut() == 2 {
		var retType reflect.Type = fnType.Out(0)
		methods := discoverErrorMethods(retType)
		if len(methods) != 0 {
			for methodName, method := range methods {
				if err := RegisterFunc(name+"::"+methodName, method.Func.Interface()); err != nil {
					return fmt.Errorf("%s::%s: %w", name, methodName, err)
				}
			}
		}
	}

	return nil
}

type Unmarshaler interface {
	UnmarshalArgNode(*ArgNode) error
}

type Asserter interface {
	Assert() Assert
}

func discoverErrorMethods(refType reflect.Type) map[string]reflect.Method {
	if refType == nil {
		return nil
	}

	// Interface types have zero-value Func fields on methods; skip them
	if refType.Kind() == reflect.Interface {
		return nil
	}

	switch refType.Kind() {
	case reflect.Pointer:
	default:
		refType = reflect.PointerTo(refType)
	}

	methods := make(map[string]reflect.Method)

	for i := 0; i < refType.NumMethod(); i++ {
		m := refType.Method(i)
		if m.PkgPath != "" {
			continue
		}

		mt := m.Type
		numOut := mt.NumOut()
		if numOut == 0 {
			continue
		}

		lastOut := mt.Out(numOut - 1)
		if lastOut != errorType {
			continue
		}

		methods[m.Name] = m
	}

	return methods
}

func buildFuncArgsAssert(fnType reflect.Type) (Assert, bool, error) {
	numIn := fnType.NumIn()
	switch numIn {
	case 0:
		return Assert{Type: "map", Sub: AssertMap{}}, false, nil
	case 1:
		argType := fnType.In(0)
		argAssert, err := ParseStruct(argType)
		if err != nil {
			return Assert{}, false, err
		}
		return argAssert, false, nil
	default:
		sub := make(AssertList, numIn)
		for i := 0; i < numIn; i++ {
			argType := fnType.In(i)
			argAssert, err := ParseStruct(argType)
			if err != nil {
				return Assert{}, false, err
			}
			sub[i] = argAssert
		}
		return Assert{
			Type:    "list",
			SubList: sub,
		}, true, nil
	}
}

func _specAssert(fnType reflect.Type, spec *ArgNode, listMode bool) ([]reflect.Value, error) {
	numIn := fnType.NumIn()
	values := make([]reflect.Value, numIn)
	if numIn == 0 {
		return values, nil
	}

	if spec == nil {
		spec = &ArgNode{Type: "null"}
	}

	if listMode {
		if spec == nil {
			spec = &ArgNode{Type: "list", Value: []*ArgNode{}}
		}
		if spec.Type != "list" {
			return nil, fmt.Errorf("function expects list, got %s", spec.Type)
		}
		listNodes := spec.ToList()
		for len(listNodes) < numIn {
			listNodes = append(listNodes, &ArgNode{Type: "null"})
		}
		spec.Value = listNodes
		for i := 0; i < numIn; i++ {
			node := listNodes[i]
			if node == nil {
				node = &ArgNode{Type: "null"}
			}
			dst := reflect.New(fnType.In(i))
			if err := node.unmarshalValue(dst.Interface()); err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			values[i] = dst.Elem()
		}
		return values, nil
	}

	if numIn == 1 {
		dst := reflect.New(fnType.In(0))
		if err := spec.unmarshalValue(dst.Interface()); err != nil {
			return nil, err
		}
		values[0] = dst.Elem()
		return values, nil
	}

	return values, nil
}

func _retAssert(method reflect.Type) (Assert, error) {
	switch method.NumOut() {
	case 1:
		return Assert{Type: "null"}, nil
	case 2:
		return ParseStruct(method.Out(0))
	default:
		return Assert{}, fmt.Errorf("method %s has unsupported return values", method.Name())
	}
}
