package groupexp

import "github.com/dlclark/regexp2"

type GroupRegexp []*regexp2.Regexp

func (r GroupRegexp) MatchString(k string) bool {
	ru := []rune(k)
	for _, v := range r {
		if ok, _ := v.MatchRunes(ru); ok {
			return true
		}
	}
	return false
}
func (r GroupRegexp) String() (ret []string) {
	for _, v := range r {
		ret = append(ret, v.String())
	}
	return
}

func NewGroupRegexp(exps []string) (GroupRegexp, error) {
	g := make(GroupRegexp, len(exps))
	for i, v := range exps {
		exp, err := regexp2.Compile(v, regexp2.RE2)
		if err != nil {
			return nil, err
		}
		g[i] = exp
	}
	return g, nil
}
func MustCompileRegexp(exps []string) GroupRegexp {
	g := make(GroupRegexp, len(exps))
	for i, v := range exps {
		g[i] = regexp2.MustCompile(v, regexp2.RE2)
	}
	return g
}
