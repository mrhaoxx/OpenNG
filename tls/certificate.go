package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/mrhaoxx/OpenNG/dns"
	utils "github.com/mrhaoxx/OpenNG/utils"
)

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
	if cert := m.lookup.Lookup(dnsname); cert != nil {
		return cert.(*tls.Certificate)
	} else {
		panic(errors.New("no certificate for " + dnsname))
	}
}

func (m *tlsMgr) LoadCertificate(certfile, keyfile string) error {
	c, e := tls.LoadX509KeyPair(certfile, keyfile)
	if e != nil {
		return e
	} else {

		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])

		m.muCerts.Lock()
		m.lookup.Refresh()

		m.certs[certfile] = Cert{
			Certificate: &c,
			dnsnames:    utils.MustCompileRegexp(dns.Dnsnames2Regexps(c.Leaf.DNSNames)),
			certfile:    certfile,
		}
		m.muCerts.Unlock()

		return nil
	}
}

func (m *tlsMgr) ResetCertificates() {
	m.muCerts.Lock()
	m.lookup.Refresh()
	m.certs = make(map[string]Cert)
	m.muCerts.Unlock()
}

func (mgr *tlsMgr) GetActiveCertificates() []Cert {
	mgr.muCerts.RLock()
	defer mgr.muCerts.RUnlock()
	var certs []Cert
	for _, v := range mgr.certs {
		certs = append(certs, v)
	}
	return certs
}
