package netgatecmd

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/net"
)

func AssertArg(node *netgate.ArgNode, assertions netgate.Assert) error {
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
		if assertions.Forced && assertions.Default != nil && assertions.Type != "url" {
			if !reflect.DeepEqual(node.Value, assertions.Default) {
				return fmt.Errorf("forced field not met requirements wanted: %v, got: %v", assertions.Default, node.Value)
			}
		}
	}

	switch assertions.Type {
	case "map":
		if node.Value == nil {
			node.Value = map[string]*netgate.ArgNode{}
		}

		if subnodes, ok := node.Value.(map[string]*netgate.ArgNode); ok {
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
							node := &netgate.ArgNode{
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
			node.Value = []*netgate.ArgNode{}
			return nil
		}

		realnodes, ok := node.Value.([]*netgate.ArgNode)
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
			node.Value = []*net.URL{}
			return nil
		}
		realnode, ok := node.Value.(*net.URL)
		if !ok {
			return fmt.Errorf("expected url, got %T", node.Value)
		}

		if assertions.Default != nil {
			assertnode := assertions.Default.(*net.URL)

			if assertions.Forced && realnode.Interface != assertnode.Interface {
				return fmt.Errorf("url interface mismatch: %s != %s", realnode.Interface, assertnode.Interface)
			}

			if assertnode.Interface != "" {

				if realnode.Interface == "" {
					realnode.Interface = assertnode.Interface
				}
			}
			if assertnode.URL.Scheme != "" {
				if assertions.Forced && realnode.URL.Scheme != assertnode.URL.Scheme {
					return fmt.Errorf("url scheme mismatch: %s != %s", realnode.URL.Scheme, assertnode.URL.Scheme)
				}
				if realnode.URL.Scheme == "" {
					realnode.URL.Scheme = assertnode.URL.Scheme
				}
			}
			if assertnode.URL.Host != "" {
				if assertions.Forced && realnode.URL.Host != assertnode.URL.Host {
					return fmt.Errorf("url host mismatch: %s != %s", realnode.URL.Host, assertnode.URL.Host)
				}
				if realnode.URL.Host == "" {
					realnode.URL.Host = assertnode.URL.Host
				}
			}
			if assertnode.URL.Path != "" {
				if assertions.Forced && realnode.URL.Path != assertnode.URL.Path {
					return fmt.Errorf("url path mismatch: %s != %s", realnode.URL.Path, assertnode.URL.Path)
				}
				if realnode.URL.Path == "" {
					realnode.URL.Path = assertnode.URL.Path
				}
			}
			if assertnode.URL.RawQuery != "" {
				if assertions.Forced && realnode.URL.RawQuery != assertnode.URL.RawQuery {
					return fmt.Errorf("url query mismatch: %s != %s", realnode.URL.RawQuery, assertnode.URL.RawQuery)
				}
				if realnode.URL.RawQuery == "" {
					realnode.URL.RawQuery = assertnode.URL.RawQuery
				}
			}
			if assertnode.URL.RawFragment != "" {
				if assertions.Forced && realnode.URL.RawFragment != assertnode.URL.RawFragment {
					return fmt.Errorf("url fragment mismatch: %s != %s", realnode.URL.RawFragment, assertnode.URL.RawFragment)
				}
				if realnode.URL.RawFragment == "" {
					realnode.URL.RawFragment = assertnode.URL.RawFragment
				}
			}
		}
	}

	return nil
}

func IfCompatibleAndConvert(node *netgate.ArgNode, assertions netgate.Assert) bool {

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
			if m, ok := node.Value.(map[string]*netgate.ArgNode); ok {
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
			node.Value = &net.URL{
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
	}

	return false
}
