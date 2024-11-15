package tcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"reflect"
	"time"

	utils "github.com/mrhaoxx/OpenNG/utils"
)

const (
	KeyTLS         = "tls"
	KeyTlsSni      = "sni"
	KeyUnkownBytes = "unkownheadbytes"
	KeyHTTPRequest = "http"
)

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(&utils.RoConn{Reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

type Detector func(io.Reader, *Conn) string

type Detect struct {
	Dets []Detector

	Timeout         time.Duration
	TimeoutProtocol string
}

// var detectors = []detector{
// 	detecttls,
// 	detectproxyproto,
// 	detectssh,
// 	detectrdp,
// 	detecthttp,
// }

func (det *Detect) Handle(c *Conn) SerRet {
	raw := c.TopConn()
	buf := &BufferedReader{
		source:     raw,
		buffer:     bytes.Buffer{},
		bufferRead: 0,
		bufferSize: 0,
		sniffing:   true,
		lastErr:    nil,
	}
	c.Reuse(&utils.RwConn{
		Reader:  buf,
		Writer:  raw,
		Rawconn: raw,
	})
	if det.Timeout > 0 {
		raw.SetReadDeadline(time.Now().Add(det.Timeout))
		defer raw.SetReadDeadline(time.Time{})
	}
	var proto string
	for i, f := range det.Dets {
		if proto = f(buf, c); proto != "" {
			break
		}
		if i == 0 && buf.buffer.Len() == 0 {
			proto = det.TimeoutProtocol
			break
		}
		buf.Reset(true)
	}
	if proto == "" {
		proto = "UNKNOWN"
		c.Store(KeyUnkownBytes, buf.buffer.String())
	}
	buf.Reset(false)

	c.IdentifiyProtocol(proto)
	return Upgrade
}

func DetectHTTP(r io.Reader, c *Conn) string {
	rr, err := http.ReadRequest(bufio.NewReader(r))
	if err != nil {
		return ""
	}
	c.Store(KeyHTTPRequest, rr)
	return "HTTP1"
}

func DetectTLS(r io.Reader, c *Conn) string {
	a, err := readClientHello(r)
	if err != nil {
		return ""
	}
	c.Store(KeyTLS, a)
	c.Store(KeyTlsSni, a.ServerName)
	return "TLS"
}

func DetectSSH(r io.Reader, _ *Conn) string {
	var buf = make([]byte, 3)
	_, err := r.Read(buf)
	if err != nil {
		return ""
	}
	if reflect.DeepEqual(buf[:3], []byte("\u0053\u0053\u0048")) {
		return "SSH"
	}
	return ""
}

func DetectRDP(r io.Reader, _ *Conn) string {
	var buf = make([]byte, 3)
	_, err := r.Read(buf)
	if err != nil {
		return ""
	}
	if reflect.DeepEqual(buf[:3], []byte("\u0003\u0000\u0000")) {
		return "RDP"
	}
	return ""
}

func DetectPROXYPROTOCOL(r io.Reader, _ *Conn) string {
	var buf = make([]byte, 12)
	_, err := r.Read(buf)
	if err != nil {
		return ""
	}
	if reflect.DeepEqual(buf[:12], []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")) {
		return "PROXY"
	}
	return ""
}

func DetectSOCKS5(r io.Reader, _ *Conn) string {
	var buf = make([]byte, 2)
	_, err := r.Read(buf)
	if err != nil {
		return ""
	}
	if reflect.DeepEqual(buf[:2], []byte("\u0005\u0001")) {
		return "SOCKS5"
	}
	return ""
}
