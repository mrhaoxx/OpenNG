package auth

import (
	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
)

type policy struct {
	name string

	allowance bool

	users map[string]bool

	hosts groupexp.GroupRegexp
	// hup   *lookup.BufferedLookup

	paths groupexp.GroupRegexp
}

// 0 -> next;1 -> refuse;2 -> accept
func (p *policy) check(username string, path string) uint8 {
	if p.users[""] || p.users[username] || (p.users["*"] && username != "") {
		if p.paths == nil || p.paths.MatchString(path) {
			if p.allowance {
				return 2
			} else {
				return 1
			}
		}
	}
	return 0
}

func (mgr *PolicyBaseAuth) determine(host, path, user string) (v uint8) {
	pls := mgr.policyLookupBuf.Lookup(host)
	if len(pls) == 0 {
		return 0
	}

	for _, p := range pls {
		v := p.check(user, path)
		// fmt.Println(p.name, host, path, user, v)
		if v != 0 {
			return v
		}
	}

	return 0
}

func (LGM *PolicyBaseAuth) AddPolicy(name string, allow bool, users []string, hosts groupexp.GroupRegexp, paths groupexp.GroupRegexp) error {
	p := &policy{
		name:      name,
		allowance: allow,
		users:     map[string]bool{},
		hosts:     hosts,
		// hup:       nil,
		paths: nil,
	}
	for _, u := range users {
		p.users[u] = true
	}

	p.paths = paths

	LGM.policies = append(LGM.policies, p)
	LGM.policyLookupBuf.Refresh()
	return nil
}
