package http

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	goproxy "golang.org/x/net/proxy"
)

type httpsDialer struct {
	tls *tls.Config
}

var HttpsDialer = httpsDialer{}

func (d *httpsDialer) Dial(network, addr string) (c net.Conn, err error) {
	return tls.Dial("tcp", addr, d.tls)
}

type httpProxy struct {
	proxyurl *url.URL
	forward  goproxy.Dialer
}

func newHTTPProxy(uri *url.URL, forward goproxy.Dialer) (goproxy.Dialer, error) {
	s := new(httpProxy)
	s.forward = forward
	s.proxyurl = uri

	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the https client connection.
	c, err := s.forward.Dial("tcp", s.proxyurl.Host)
	if err != nil {
		return nil, err
	}

	// HACK. http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	req.Close = false
	if s.proxyurl.User != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(s.proxyurl.User.Username(), func() string { pwd, _ := s.proxyurl.User.Password(); return pwd }()))
	}
	req.Header.Set("User-Agent", "OpenNG Proxy Forward")

	err = req.Write(c)
	if err != nil {
		c.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		c.Close()
		err = fmt.Errorf("forward http proxy error with status %d", resp.StatusCode)
		return nil, err
	}

	return c, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func init() {
	goproxy.RegisterDialerType("http", newHTTPProxy)
	goproxy.RegisterDialerType("https", newHTTPProxy)
}
