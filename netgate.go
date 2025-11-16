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
var member_func_registry = map[string]map[string]MemberFunction{}

var refs = map[string]Inst{}
var asserterInterfaceType = reflect.TypeFor[Asserter]()
var unmarshalerInterfaceType = reflect.TypeFor[Unmarshaler]()
var defaulterInterfaceType = reflect.TypeFor[Defaulter]()
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

func MemberFunctionRegistry() map[string]map[string]MemberFunction {
	return member_func_registry
}

type Inst func(*ArgNode) (any, error)

type AssertMap map[string]Assert

type Assert struct {
	Type     string
	Required bool
	Forced   bool
	Sub      AssertMap

	Default any

	// Enum         []any
	// AllowNonEnum bool
	Desc string

	Struct   bool
	Impls    []reflect.Type
	AllowNil bool
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
		node.applyDefaults(dst)
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

func (node *ArgNode) applyDefaults(dst reflect.Value) {
	if defaulterInterfaceType == nil || !dst.IsValid() {
		return
	}

	if dst.Type().Implements(defaulterInterfaceType) && dst.CanInterface() {
		dst.Interface().(Defaulter).MakeDefault()
		return
	}

	if dst.CanAddr() {
		addr := dst.Addr()
		if addr.Type().Implements(defaulterInterfaceType) {
			addr.Interface().(Defaulter).MakeDefault()
			return
		}
	}

	if dst.CanSet() {
		ptrType := reflect.PointerTo(dst.Type())
		if ptrType.Implements(defaulterInterfaceType) {
			tmp := reflect.New(dst.Type())
			tmp.Elem().Set(dst)
			tmp.Interface().(Defaulter).MakeDefault()
			dst.Set(tmp.Elem())
		}
	}
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

		// check builtin types
		if refType == reflect.TypeFor[ngnet.URL]() {
			return Assert{
				Type: "url",
			}, nil
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

			notype := field.Tag.Get("type")
			if notype != "" {
				fieldAssert.Type = notype
			}
			sub[key] = fieldAssert
		}
		defaultValue, _ := structDefaultFromMakeDefault(refType)
		return Assert{
			Type:    "map",
			Sub:     sub,
			Default: defaultValue,
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

func structDefaultFromMakeDefault(refType reflect.Type) (any, bool) {
	if refType == nil || defaulterInterfaceType == nil {
		return nil, false
	}

	ptrType := reflect.PointerTo(refType)
	if ptrType.Implements(defaulterInterfaceType) {
		instance := reflect.New(refType)
		instance.Interface().(Defaulter).MakeDefault()
		return instance.Elem().Interface(), true
	}

	if refType.Implements(defaulterInterfaceType) {
		instance := reflect.New(refType).Elem()
		instance.Interface().(Defaulter).MakeDefault()
		return instance.Interface(), true
	}

	return nil, false
}

func tryCustomAsserter(refType reflect.Type) (Assert, bool) {
	if refType == nil {
		return Assert{}, false
	}

	if refType.Implements(asserterInterfaceType) {
		in := reflect.New(refType).Interface()
		// apply default if possible
		if defaulter, ok := in.(Defaulter); ok {
			defaulter.MakeDefault()
		}
		return in.(Asserter).Assert(), true
	}

	if refType.Kind() != reflect.Pointer {
		ptrType := reflect.PointerTo(refType)
		if ptrType.Implements(asserterInterfaceType) {
			in := reflect.New(refType).Interface()
			// apply default if possible
			if defaulter, ok := in.(Defaulter); ok {
				defaulter.MakeDefault()
			}
			return in.(Asserter).Assert(), true
		}
	}

	return Assert{}, false
}

func RegisterFunc[U any, V any](name string, fn func(U) (V, error)) error {
	argType := reflect.TypeOf((*U)(nil)).Elem()
	retType := reflect.TypeOf((*V)(nil)).Elem()

	args, err := ParseStruct(argType)
	if err != nil {
		return err
	}
	ret, err := ParseStruct(retType)
	if err != nil {
		return err
	}

	Register(name,
		args, ret, func(arg *ArgNode) (any, error) {
			var arginst U
			if err := arg.unmarshalValue(&arginst); err != nil {
				return nil, err
			}
			return fn(arginst)
		})

	if err := registerMemberMethods(name, retType); err != nil {
		return err
	}

	return nil

}

type Unmarshaler interface {
	UnmarshalArgNode(*ArgNode) error
}

type Asserter interface {
	Assert() Assert
}

type Defaulter interface {
	MakeDefault()
}

func DiscoverErrorMethods(refType reflect.Type) map[string]reflect.Method {
	if refType == nil {
		return nil
	}

	switch refType.Kind() {
	case reflect.Pointer, reflect.Interface:
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

func registerMemberMethods(name string, retType reflect.Type) error {
	methods := DiscoverErrorMethods(retType)
	if len(methods) == 0 {
		return nil
	}

	for methodName, method := range methods {
		methodName := methodName
		method := method
		if err := registerMemberMethod(name, method); err != nil {
			return fmt.Errorf("%s::%s: %w", name, methodName, err)
		}
	}

	return nil
}

func registerMemberMethod(name string, method reflect.Method) error {
	if method.Type.IsVariadic() {
		return nil
	}

	specType, err := buildMemberSpecType(method)
	if err != nil {
		return err
	}

	argsAssert, err := ParseStruct(specType)
	if err != nil {
		return err
	}

	retAssert, err := buildMemberReturnAssert(method)
	if err != nil {
		return err
	}

	fullName := fmt.Sprintf("%s::%s", name, method.Name)
	if _, exists := refs[fullName]; exists {
		return nil
	}

	Register(fullName, argsAssert, retAssert, buildMemberMethodInst(method, specType))

	if _, ok := member_func_registry[name]; !ok {
		member_func_registry[name] = map[string]MemberFunction{}
	}
	member_func_registry[name][method.Name] = MemberFunction{
		FullName: fullName,
		Args:     argsAssert,
		Ret:      retAssert,
	}

	return nil
}

func buildMemberSpecType(method reflect.Method) (reflect.Type, error) {
	numIn := method.Type.NumIn()
	if numIn == 0 {
		return nil, fmt.Errorf("method %s has no receiver", method.Name)
	}

	fields := make([]reflect.StructField, 0, numIn)
	fields = append(fields, reflect.StructField{
		Name: "Ptr",
		Type: method.Type.In(0),
		Tag:  `ng:"ptr"`,
	})

	for i := 1; i < numIn; i++ {
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("Arg%d", i-1),
			Type: method.Type.In(i),
			Tag:  reflect.StructTag(fmt.Sprintf(`ng:"arg%d"`, i-1)),
		})
	}

	return reflect.StructOf(fields), nil
}

func buildMemberReturnAssert(method reflect.Method) (Assert, error) {
	switch method.Type.NumOut() {
	case 1:
		return Assert{Type: "null"}, nil
	case 2:
		return ParseStruct(method.Type.Out(0))
	default:
		return Assert{}, fmt.Errorf("method %s has unsupported return values", method.Name)
	}
}

func buildMemberMethodInst(method reflect.Method, specType reflect.Type) Inst {
	return func(arg *ArgNode) (any, error) {
		specValue := reflect.New(specType)
		if err := arg.unmarshalValue(specValue.Interface()); err != nil {
			return nil, err
		}

		val := specValue.Elem()
		recv := val.Field(0)
		if !recv.IsValid() || recv.IsZero() {
			return nil, fmt.Errorf("ptr is nil")
		}

		receiver := recv.Interface()
		methodValue := reflect.ValueOf(receiver).MethodByName(method.Name)
		if !methodValue.IsValid() {
			return nil, fmt.Errorf("method %s not found on receiver", method.Name)
		}

		numIn := method.Type.NumIn()
		args := make([]reflect.Value, numIn-1)
		for i := 1; i < numIn; i++ {
			args[i-1] = val.Field(i)
		}

		result := methodValue.Call(args)
		numOut := method.Type.NumOut()

		if numOut == 1 {
			if errVal, _ := result[0].Interface().(error); errVal != nil {
				return nil, errVal
			}
			return nil, nil
		}

		if errVal, _ := result[numOut-1].Interface().(error); errVal != nil {
			return nil, errVal
		}

		return result[0].Interface(), nil
	}
}
