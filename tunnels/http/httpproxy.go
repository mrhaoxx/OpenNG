package http

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/mrhaoxx/OpenNG/net"
)

type HttpProxyInterface struct {
	proxyurl   *url.URL
	underlying net.Interface
}

func (s *HttpProxyInterface) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, net.ErrTCPOnly
	}

	c, err := s.underlying.Dial("tcp", s.proxyurl.Host)
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("forward http proxy error with status %d", resp.StatusCode)
	}

	return c, nil
}

func (s *HttpProxyInterface) Listen(network, address string) (net.Listener, error) {
	return nil, net.ErrListenNotSupport
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
