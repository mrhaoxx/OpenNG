package tls

func (mgr *tlsMgr) GetCerts() []Cert {
	mgr.muCerts.RLock()
	defer mgr.muCerts.RUnlock()
	var certs []Cert
	for _, v := range mgr.certs {
		certs = append(certs, v)
	}
	return certs
}
