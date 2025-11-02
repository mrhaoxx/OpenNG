package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	gonet "net"
	"net/http"
	"net/url"

	"github.com/mrhaoxx/OpenNG/pkg/net"
)

type HttpProxyInterface struct {
	Proxyurl *net.URL
}

func (s *HttpProxyInterface) DialContext(ctx context.Context, network, addr string) (gonet.Conn, error) {
	if network != "tcp" {
		return nil, net.ErrTCPOnly
	}

	c, err := s.Proxyurl.Underlying.DialContext(ctx, "tcp", s.Proxyurl.Host)
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
	if s.Proxyurl.User != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicAuth(s.Proxyurl.User.Username(), func() string { pwd, _ := s.Proxyurl.User.Password(); return pwd }()))
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

func (s *HttpProxyInterface) Dial(network, addr string) (gonet.Conn, error) {
	return s.DialContext(context.Background(), network, addr)
}

func (s *HttpProxyInterface) Listen(network, address string) (gonet.Listener, error) {
	return nil, net.ErrListenNotSupport
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
