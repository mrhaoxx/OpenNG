package dns

import "strings"

func Dnsnames2Regexps(dnsnames []string) []string {
	var out []string
	for _, v := range dnsnames {
		v = strings.ReplaceAll(v, ".", "\\.")
		v = strings.ReplaceAll(v, "*", ".*")
		out = append(out, "^"+v+"$")
	}
	return out
}
func Dnsname2Regexp(dnsname string) (v string) {
	v = strings.ReplaceAll(dnsname, ".", "\\.")
	v = strings.ReplaceAll(v, "*", ".*")
	return "^" + v + "$"
}
