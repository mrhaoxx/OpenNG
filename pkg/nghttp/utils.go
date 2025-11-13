package nghttp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
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

type redirectTLS struct{}

func (redirectTLS) HandleTCP(conn *ngtcp.Conn) ngtcp.Ret {
	http.Serve(ngnet.ConnGetSocket(conn.TopConn()), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusPermanentRedirect)
	}))
	return ngtcp.Close
}

var Redirect2TLS = redirectTLS{}

var _ ngtcp.Service = redirectTLS{}

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

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func copyResponse(rw http.ResponseWriter, resp *http.Response) error {
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()

	_, err := io.Copy(rw, resp.Body)
	return err
}

func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string) {
	hostPort = u.Host
	hostNoPort = u.Host
	if i := strings.LastIndex(u.Host, ":"); i > strings.LastIndex(u.Host, "]") {
		hostNoPort = hostNoPort[:i]
	} else {
		switch u.Scheme {
		case "wss":
			hostPort += ":443"
		case "https":
			hostPort += ":443"
		default:
			hostPort += ":80"
		}
	}
	return hostPort, hostNoPort
}

func EchoVerbose(ctx *HttpCtx) Ret {
	ctx.WriteString("Method: " + ctx.Req.Method + "\n")
	ctx.WriteString("URL: " + ctx.Req.URL.String() + "\n")
	ctx.WriteString("Proto: " + ctx.Req.Proto + "\n")
	ctx.WriteString("Host: " + ctx.Req.Host + "\n")
	ctx.WriteString("IP: " + ctx.RemoteIP + "\n")
	ctx.WriteString("RequestURI: " + ctx.Req.RequestURI + "\n")

	for name, values := range ctx.Req.Header {
		for _, value := range values {
			fmt.Fprintf(ctx.Resp, "%v: %v\n", name, value)
		}
	}

	return RequestEnd
}
