package ngtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"sync"

	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/lookup"
	ngdns "github.com/mrhaoxx/OpenNG/pkg/ngdns"
)

func certNames(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

type Cert struct {
	*tls.Certificate
	dnsnames groupexp.GroupRegexp

	certfile string
	keyfile  string
}

type TlsMgr struct {
	certs  map[string]Cert
	lookup *lookup.BufferedLookup[*tls.Certificate]

	clientCAs *x509.CertPool

	muCerts sync.RWMutex
}

func NewTlsMgr() *TlsMgr {

	var mgr = TlsMgr{
		certs: make(map[string]Cert),
	}

	mgr.lookup = lookup.NewBufferedLookup(func(s string) *tls.Certificate {
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
			dnsnames:    groupexp.MustCompileRegexp(ngdns.Dnsnames2Regexps(certNames(c.Leaf))),
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

func (m *TlsMgr) LoadClientCA(cafile string) error {
	caCert, err := os.ReadFile(cafile)
	if err != nil {
		return err
	}
	if m.clientCAs == nil {
		m.clientCAs = x509.NewCertPool()
	}
	if !m.clientCAs.AppendCertsFromPEM(caCert) {
		return errors.New("failed to parse client CA certificate: " + cafile)
	}
	return nil
}

func (m *TlsMgr) TlsConfig(cert *tls.Certificate, nextProtos []string) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   nextProtos,
	}
	if m.clientCAs != nil {
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		cfg.ClientCAs = m.clientCAs
	}
	return cfg
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

		v.dnsnames = groupexp.MustCompileRegexp(ngdns.Dnsnames2Regexps(certNames(cert.Leaf)))

		m.certs[v.certfile] = v

	}

	m.lookup.Refresh()
	return nil
}
