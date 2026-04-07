package auth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	stdhttp "net/http"

	"github.com/mrhaoxx/OpenNG/modules/lookup"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
	"github.com/mrhaoxx/OpenNG/modules/ngssh"

	gossh "golang.org/x/crypto/ssh"

	zlog "github.com/rs/zerolog/log"
)

type policyBaseAuth struct {
	policies        []*policy
	policyLookupBuf *lookup.BufferedLookup[[]*policy]

	backends backendGroup

	certMappings map[string]string // fingerprint -> username

	sessions  map[string]*session
	muSession sync.RWMutex
}

func NewPBAuth() *policyBaseAuth {
	po := &policyBaseAuth{
		sessions:     map[string]*session{},
		certMappings: map[string]string{},
	}

	po.policyLookupBuf = lookup.NewBufferedLookup(func(s string) []*policy {
		var r []*policy = nil
		for _, p := range po.policies {
			if p.hosts != nil && p.hosts.MatchString(s) {
				r = append(r, p)
			}
		}
		return r
	})

	go func() {
		for range time.Tick(time.Minute * 10) {
			po.Clean()
		}
	}()
	return po
}

func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func (mgr *policyBaseAuth) HandleAuth(ctx *nghttp.HttpCtx) AuthRet {
	// First Lets get user info
	var token = ctx.RemoveCookie(verfiyCookieKey)

	var session *session
	var user string

	if token != "" {
		session = mgr.at(token)

		if session != nil {
			user = session.username
			session.renew()
		}
	}

	// If no valid session, try client certificate authentication
	if session == nil && ctx.Req.TLS != nil && len(ctx.Req.TLS.PeerCertificates) > 0 {
		fp := certFingerprint(ctx.Req.TLS.PeerCertificates[0])
		username, ok := mgr.certMappings[fp]
		if !ok {
			username, ok, _ = mgr.backends.CheckClientCert(fp)
		}
		if ok {
			token = mgr.generateSession(username, -1)
			session = mgr.at(token)
			user = username

			ctx.SetCookie(&stdhttp.Cookie{
				Name:     verfiyCookieKey,
				Value:    token,
				Domain:   nghttp.GetRootDomain(ctx.Req.Host),
				Secure:   true,
				Path:     "/",
				Expires:  time.Now().Add(3 * 24 * time.Hour),
				SameSite: stdhttp.SameSiteNoneMode,
			})

			zlog.Info().
				Str("type", "auth/login").
				Str("method", "clientcert").
				Str("user", username).
				Str("fingerprint", fp).
				Str("reqid", ctx.Id).
				Str("ip", ctx.RemoteIP).
				Int("port", ctx.RemotePort).
				Msg("")
		}
	}

	switch mgr.determine(ctx.Req.Host, ctx.Req.URL.Path, user) {
	case 2:
		if session != nil {
			atomic.AddUint64(&session.active, uint64(1))

			ctx.OnClose(func(*nghttp.HttpCtx) {
				atomic.AddUint64(&session.active, ^uint64(0))
			})
		}

		return Accept
	case 0:
		return Continue // no hit
	case 1:
		url := nghttp.PrefixNg + PrefixAuth + PrefixAuthPolicy + "/login?r=" + base64.URLEncoding.EncodeToString([]byte(ctx.Req.RequestURI))
		ctx.Redirect(url, nghttp.StatusFound) //auth required
	}

	return Deny
}

func (mgr *policyBaseAuth) AddBackends(_src []PolicyBackend) {
	mgr.backends = append(mgr.backends, _src...)
}

func (mgr *policyBaseAuth) AddCertMapping(fingerprint string, username string) {
	mgr.certMappings[fingerprint] = username
}

func (mgr *policyBaseAuth) CheckSSHKey(ctx *ngssh.Ctx, key gossh.PublicKey) bool {
	ok, _ := mgr.backends.CheckSSHKey(ctx, key)
	return ok
}
