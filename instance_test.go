package ng

import (
	"errors"
	"strings"
	"testing"
)

func TestRegisterDuplicateKindPanics(t *testing.T) {
	Register("test::dup", Assert{Type: "null"}, Assert{}, func(*ArgNode) (any, error) { return nil, nil })
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate kind registration")
		}
	}()
	Register("test::dup", Assert{Type: "null"}, Assert{}, func(*ArgNode) (any, error) { return nil, nil })
}

func TestAssertArgExprCompileCheck(t *testing.T) {
	compileErr := errors.New("unexpected token")
	assert := Assert{
		Type: "expr",
		ExprCheck: func(source string) error {
			if source == "bad(" {
				return compileErr
			}
			return nil
		},
	}

	good := &ArgNode{Type: "string", Value: "tcp.IP() == \"1.2.3.4\""}
	if err := AssertArg(good, assert); err != nil {
		t.Fatalf("valid expr rejected: %v", err)
	}
	if good.Type != "expr" {
		t.Fatalf("expected node retagged to expr, got %s", good.Type)
	}

	bad := &ArgNode{Type: "string", Value: "bad("}
	err := AssertArg(bad, assert)
	if err == nil {
		t.Fatal("invalid expr passed AssertArg")
	}
	if !errors.Is(err, compileErr) {
		t.Fatalf("expected compile error to surface, got: %v", err)
	}
}

func TestAssertArgExprWithoutCheckStillConverts(t *testing.T) {
	node := &ArgNode{Type: "string", Value: "anything"}
	if err := AssertArg(node, Assert{Type: "expr"}); err != nil {
		t.Fatalf("expr without ExprCheck should convert: %v", err)
	}
}

func TestConvertErrorsAreDescriptive(t *testing.T) {
	cases := []struct {
		name    string
		node    *ArgNode
		assert  Assert
		wantSub string
	}{
		{"bad duration", &ArgNode{Type: "string", Value: "10x"}, Assert{Type: "duration"}, "invalid duration"},
		{"bad regexp", &ArgNode{Type: "string", Value: "("}, Assert{Type: "regexp"}, "invalid regexp"},
		{"bad hostname", &ArgNode{Type: "string", Value: "host name!"}, Assert{Type: "hostname"}, "invalid hostname"},
		{"no conversion", &ArgNode{Type: "int", Value: 1}, Assert{Type: "map"}, "type incompatible"},
	}
	for _, c := range cases {
		err := IfCompatibleAndConvert(c.node, c.assert)
		if err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Fatalf("%s: error %q does not contain %q", c.name, err, c.wantSub)
		}
	}
}

type stopRecorder struct {
	name string
	log  *[]string
}

func (s *stopRecorder) Stop() { *s.log = append(*s.log, s.name) }

func TestSpaceStopReverseOrder(t *testing.T) {
	var stopped []string

	mkInst := func(name string) Inst {
		return func(*ArgNode) (any, error) {
			return &stopRecorder{name: name, log: &stopped}, nil
		}
	}
	Register("test::stop-a", Assert{Type: "null"}, Assert{}, mkInst("a"))
	Register("test::stop-b", Assert{Type: "null"}, Assert{}, mkInst("b"))

	space := Space{
		Services:     map[string]any{},
		Refs:         Registry(),
		AssertRefs:   AssertionsRegistry(),
		ServiceKinds: map[string]string{},
	}

	root := &ArgNode{Type: "map", Value: map[string]*ArgNode{
		"Services": {Type: "map", Value: map[string]*ArgNode{
			"svc-a": {Type: "map", Value: map[string]*ArgNode{
				"kind": {Type: "string", Value: "test::stop-a"},
			}},
			"svc-b": {Type: "map", Value: map[string]*ArgNode{
				"kind": {Type: "string", Value: "test::stop-b"},
			}},
		}},
	}}

	if err := space.Apply(root, false, false); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(space.order) != 2 {
		t.Fatalf("expected 2 services in instantiation order, got %v", space.order)
	}

	space.Stop()

	if len(stopped) != 2 {
		t.Fatalf("expected 2 services stopped, got %v", stopped)
	}
	// Reverse instantiation order: last created stops first.
	wantFirst := map[string]string{"svc-a": "a", "svc-b": "b"}[space.order[1]]
	if stopped[0] != wantFirst {
		t.Fatalf("expected reverse order (first stopped = %s), got %v (order %v)", wantFirst, stopped, space.order)
	}
}

func TestSpaceStopSurvivesPanic(t *testing.T) {
	var stopped []string
	Register("test::stop-panic", Assert{Type: "null"}, Assert{}, func(*ArgNode) (any, error) {
		return &panicStopper{}, nil
	})
	Register("test::stop-ok", Assert{Type: "null"}, Assert{}, func(*ArgNode) (any, error) {
		return &stopRecorder{name: "ok", log: &stopped}, nil
	})

	space := Space{
		Services:     map[string]any{},
		Refs:         Registry(),
		AssertRefs:   AssertionsRegistry(),
		ServiceKinds: map[string]string{},
	}
	root := &ArgNode{Type: "map", Value: map[string]*ArgNode{
		"Services": {Type: "map", Value: map[string]*ArgNode{
			"bad": {Type: "map", Value: map[string]*ArgNode{
				"kind": {Type: "string", Value: "test::stop-panic"},
			}},
			"good": {Type: "map", Value: map[string]*ArgNode{
				"kind": {Type: "string", Value: "test::stop-ok"},
			}},
		}},
	}}
	if err := space.Apply(root, false, false); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	space.Stop() // must not panic

	if len(stopped) != 1 || stopped[0] != "ok" {
		t.Fatalf("good service not stopped despite sibling panic: %v", stopped)
	}
}

type panicStopper struct{}

func (*panicStopper) Stop() { panic("stop failed") }

func TestSafeInstConvertsPanicToError(t *testing.T) {
	_, err := safeInst(func(*ArgNode) (any, error) {
		panic("boom")
	}, nil)
	if err == nil {
		t.Fatal("expected error from panicking constructor")
	}
	if !strings.Contains(err.Error(), "constructor panic") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}
