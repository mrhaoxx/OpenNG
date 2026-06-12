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
