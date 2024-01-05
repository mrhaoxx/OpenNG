package tls

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"

	utils "github.com/mrhaoxx/OpenNG/utils"
)

// var GlobalCer = []tls.Certificate{}
type Cert struct {
	*tls.Certificate
	dnsnames utils.GroupRegexp
	certfile string
}

type tlsMgr struct {
	certs  map[string]Cert
	lookup *utils.BufferedLookup

	muCerts sync.RWMutex
}

func NewTlsMgr() *tlsMgr {

	var mgr = tlsMgr{
		certs: make(map[string]Cert),
	}

	mgr.lookup = utils.NewBufferedLookup(func(s string) interface{} {
		mgr.muCerts.RLock()
		defer mgr.muCerts.RUnlock()

		for _, v := range mgr.certs {
			if v.dnsnames.MatchString(s) {
				return v.Certificate
			}
		}
		return nil
	})

	return &mgr
}

func (m *tlsMgr) getCertificate(dnsname string) *tls.Certificate {
	return m.lookup.Lookup(dnsname).(*tls.Certificate)
}

func (m *tlsMgr) LoadCertificate(certfile, keyfile string) error {
	c, e := tls.LoadX509KeyPair(certfile, keyfile)
	if e != nil {
		return e
	} else {

		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])

		m.muCerts.Lock()
		m.certs[certfile] = Cert{
			Certificate: &c,
			dnsnames:    utils.MustCompileRegexp(Dnsname2Regexp(c.Leaf.DNSNames)),
			certfile:    certfile,
		}
		m.muCerts.Unlock()

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
