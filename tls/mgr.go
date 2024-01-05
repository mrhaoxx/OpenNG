package tls

import (
	"sync"

	utils "github.com/mrhaoxx/OpenNG/utils"
)

type tlsMgr struct {
	certs  map[string]certificate
	lookup *utils.BufferedLookup

	muCerts sync.RWMutex
}

func NewTlsMgr() *tlsMgr {

	var mgr = tlsMgr{
		certs: make(map[string]certificate),
	}

	mgr.lookup = utils.NewBufferedLookup(func(s string) interface{} {
		mgr.muCerts.RLock()
		defer mgr.muCerts.RUnlock()

		for k, v := range mgr.certs {
			if v.dnsnames.MatchString(s) {
				return k
			}
		}
		return "unmatched"
	})

	return &mgr
}
