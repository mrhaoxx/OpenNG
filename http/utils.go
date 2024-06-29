package http

import "strings"

func IsDoubleTailDomainSuffix(domain string) bool {
	switch domain {
	case "edu.cn":
	case "org.cn":
	case "com.cn":
	case "gov.cn":
	case "co.uk":
	case "co.jp":
	case "com.hk":
	default:
		return false
	}
	return true
}

func GetRootDomain(host string) string {
	var Maindomain string
	n := strings.Split(host, ".")
	if len(n) >= 2 {
		last2 := strings.Join(n[len(n)-2:], ".")
		if IsDoubleTailDomainSuffix(last2) {
			Maindomain = strings.Join(n[len(n)-3:], ".")
		} else {
			Maindomain = strings.Join(n[len(n)-2:], ".")
		}
		Maindomain = strings.Split(Maindomain, ":")[0]
	} else {
		Maindomain = host
	}
	return Maindomain
}
