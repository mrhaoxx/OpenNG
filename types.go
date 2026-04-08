package ng

import (
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

// HostnameSlice is a list of compiled hostname patterns for use in config structs.
// Assert type: list of hostname. Unmarshals to compiled regexps.
type HostnameSlice groupexp.GroupRegexp

func (*HostnameSlice) Assert() Assert {
	return Assert{
		Type: "list",
		Sub:  AssertMap{"_": {Type: "hostname"}},
	}
}

func (h *HostnameSlice) UnmarshalArgNode(node *ArgNode) error {
	*h = nil
	for _, v := range node.ToList() {
		if v == nil || v.Value == nil {
			continue
		}
		*h = append(*h, v.ToRegexp())
	}
	return nil
}

func (h HostnameSlice) GroupRegexp() groupexp.GroupRegexp {
	return groupexp.GroupRegexp(h)
}

func (h HostnameSlice) MatchString(s string) bool {
	return groupexp.GroupRegexp(h).MatchString(s)
}

// RegexpSlice is a list of compiled regexp patterns for use in config structs.
// Assert type: list of regexp. Unmarshals to compiled regexps.
type RegexpSlice groupexp.GroupRegexp

func (*RegexpSlice) Assert() Assert {
	return Assert{
		Type: "list",
		Sub:  AssertMap{"_": {Type: "regexp"}},
	}
}

func (r *RegexpSlice) UnmarshalArgNode(node *ArgNode) error {
	*r = nil
	for _, v := range node.ToList() {
		if v == nil || v.Value == nil {
			continue
		}
		*r = append(*r, v.ToRegexp())
	}
	return nil
}

func (r RegexpSlice) GroupRegexp() groupexp.GroupRegexp {
	return groupexp.GroupRegexp(r)
}

func (r RegexpSlice) MatchString(s string) bool {
	return groupexp.GroupRegexp(r).MatchString(s)
}
