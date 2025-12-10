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
	keyfile  string
}

type TlsMgr struct {
	certs  map[string]Cert
	lookup *utils.BufferedLookup[*tls.Certificate]
	snis   utils.GroupRegexp

	muCerts sync.RWMutex
}

func NewTlsMgr(snis utils.GroupRegexp) *TlsMgr {

	var mgr = TlsMgr{
		certs: make(map[string]Cert),
		snis:  snis,
	}

	mgr.lookup = utils.NewBufferedLookup(func(s string) *tls.Certificate {
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

func (m *TlsMgr) getCertificate(dnsname string) *tls.Certificate {
	if cert := m.lookup.Lookup(dnsname); cert != nil {
		return cert
	} else {
		panic(errors.New("no certificate for " + dnsname))
	}
}

func (m *TlsMgr) LoadCertificate(certfile, keyfile string) error {
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
			keyfile:     keyfile,
		}
		m.muCerts.Unlock()

		return nil
	}
}

func (m *TlsMgr) ResetCertificates() {
	m.muCerts.Lock()
	m.lookup.Refresh()
	m.certs = make(map[string]Cert)
	m.muCerts.Unlock()
}

func (mgr *TlsMgr) GetActiveCertificates() []Cert {
	mgr.muCerts.RLock()
	defer mgr.muCerts.RUnlock()
	var certs []Cert
	for _, v := range mgr.certs {
		certs = append(certs, v)
	}
	return certs
}

func (m *TlsMgr) Reload() error {
	m.muCerts.Lock()
	defer m.muCerts.Unlock()

	for _, v := range m.certs {
		cert, err := tls.LoadX509KeyPair(v.certfile, v.keyfile)
		if err != nil {
			return err
		}
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		v.Certificate = &cert

		v.dnsnames = utils.MustCompileRegexp(dns.Dnsnames2Regexps(cert.Leaf.DNSNames))

		m.certs[v.certfile] = v

	}

	m.lookup.Refresh()
	return nil
}
