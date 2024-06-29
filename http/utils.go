package http

import (
	"crypto/tls"
	"strings"

	"github.com/dlclark/regexp2"
)

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

var _my_cipher_suit = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

var regexpforproxy = []*regexp2.Regexp{regexp2.MustCompile("^/proxy/trace$", 0)}
