package ng

import (
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngdns"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

//go:embed NetGATE.svg
var logo_svg []byte

func Logo() []byte {
	return logo_svg
}

const (
	ServerSign = "OpenNG"
)

var args_asserts = map[string]Assert{}
var ret_asserts = map[string]Assert{}

var refs = map[string]Inst{}
var asserterInterfaceType = reflect.TypeFor[Asserter]()
var unmarshalerInterfaceType = reflect.TypeFor[Unmarshaler]()

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

type Inst func(*ArgNode) (any, error)

type AssertMap map[string]Assert

type Assert struct {
	Type     string
	Required bool
	Forced   bool
	Sub      AssertMap

	Default any

	Enum         []any
	AllowNonEnum bool
	Desc         string

	Struct   bool
	Impls    []reflect.Type
	AllowNil bool
}

func TypeOf[T any]() reflect.Type {
	var z *T
	return reflect.TypeOf(z).Elem()
}

type ArgNode struct {
	Type  string
	Value any
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
		if v.Value == nil || v.Type != "regexp" {
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

	if dst.Kind() == reflect.Interface {
		dst.Set(reflect.ValueOf(node.interfaceValue()))
		return nil
	}

	if dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return node.assignValue(dst.Elem())
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

		tag := fieldInfo.Tag.Get("ng")
		if tag == "-" {
			continue
		}

		fieldValue := dst.Field(i)

		if fieldInfo.Anonymous && tag == "" {
			if err := node.unmarshalValue(fieldValue); err != nil {
				return err
			}
			continue
		}

		key := fieldInfo.Name
		if tag != "" {
			key = tag
		}

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
		// check custom asserter
		if assert, ok := tryCustomAsserter(refType); ok {
			return assert, nil
		}

		sub := AssertMap{}
		numFields := refType.NumField()
		for i := 0; i < numFields; i++ {
			field := refType.Field(i)
			if !field.IsExported() {
				continue
			}

			tag := field.Tag.Get("ng")
			if tag == "-" {
				continue
			}

			key := field.Name
			if tag != "" {
				key = tag
			}

			fieldAssert, err := ParseStruct(field.Type)
			if err != nil {
				return Assert{}, err
			}
			sub[key] = fieldAssert
		}
		return Assert{
			Type: "map",
			Sub:  sub,
		}, nil
	case reflect.Ptr:
		return Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				refType,
			},
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
		return Assert{}, fmt.Errorf("unsupported type: %s", refType)
	}
}

func tryCustomAsserter(refType reflect.Type) (Assert, bool) {
	if refType == nil {
		return Assert{}, false
	}

	if refType.Implements(asserterInterfaceType) {
		return reflect.New(refType).Interface().(Asserter).Assert(), true
	}

	if refType.Kind() != reflect.Pointer {
		ptrType := reflect.PointerTo(refType)
		if ptrType.Implements(asserterInterfaceType) {
			return reflect.New(refType).Interface().(Asserter).Assert(), true
		}
	}

	return Assert{}, false
}

func RegisterFunc[U any, V any](name string, fn func(U) (V, error)) {

	args, _ := ParseStruct(reflect.TypeOf((*U)(nil)).Elem())
	ret, _ := ParseStruct(reflect.TypeOf((*V)(nil)).Elem())

	Register(name,
		args, ret, func(arg *ArgNode) (any, error) {
			var arginst U
			if err := arg.unmarshalValue(&arginst); err != nil {
				return nil, err
			}
			return fn(arginst)
		})
}

type Unmarshaler interface {
	UnmarshalArgNode(*ArgNode) error
}

type Asserter interface {
	Assert() Assert
}
