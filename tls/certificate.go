package tls

import (
	"crypto/tls"
	"crypto/x509"
	"strings"

	utils "github.com/haoxingxing/OpenNG/utils"
)

// var GlobalCer = []tls.Certificate{}
type certificate struct {
	*tls.Certificate
	dnsnames utils.GroupRegexp
}

func (m *tlsMgr) getCertificate(dnsname string) *tls.Certificate {
	return m.certs[m.lookup.Lookup(dnsname).(string)].Certificate
}

func (m *tlsMgr) LoadCertificate(certfile, keyfile string) error {
	c, e := tls.LoadX509KeyPair(certfile, keyfile)
	if e != nil {
		return e
	} else {
		// if watch {
		// 	certwatchlist[certfile] = keyfile
		// 	watcher.Add(certfile)
		// }
		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])

		m.certs[certfile] = certificate{
			Certificate: &c,
			dnsnames:    utils.MustCompileRegexp(Dnsname2Regexp(c.Leaf.DNSNames)),
		}
		return nil
	}
}

func Dnsname2Regexp(dnsnames []string) []string {
	var out []string
	for _, v := range dnsnames {
		v = strings.ReplaceAll(v, ".", "\\.")
		v = strings.ReplaceAll(v, "*", ".*")
		out = append(out, "^"+v+"$")
	}
	return out
}
