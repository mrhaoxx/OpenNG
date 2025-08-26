package http

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/utils"

	"github.com/andybalholm/brotli"
)

// HttpCtx is the context of a http request
// It holds the request and response writer
type HttpCtx struct {
	//unsync readonly
	Id        string
	starttime time.Time

	RemoteIP   string
	RemotePort int

	Req  *http.Request
	Resp *NgResponseWriter

	conn *tcp.Conn

	closing chan struct{}

	kill func()

	onClose []func(*HttpCtx)
}

// Redirect redirects the request to another url
func (c *HttpCtx) Redirect(url string, code int) {
	http.Redirect(c.Resp, c.Req, url, code)
}

func (c *HttpCtx) WriteString(s string) {
	io.WriteString(c.Resp, s)
}

func (c *HttpCtx) SetCookie(k *http.Cookie) {
	http.SetCookie(c.Resp, k)
}

// RemoveCookie removes a cookie from the request.
// it modifies the orginal request header.
func (ctx *HttpCtx) RemoveCookie(key string) (value string) {
	var exists bool

	cookieHeader := ctx.Req.Header["Cookie"]
	newCookieHeader := make([]string, 0)

	for _, cookie := range cookieHeader {
		cookies := strings.Split(cookie, ";")
		for j, item := range cookies {
			if strings.Contains(item, key+"=") {
				value = strings.TrimPrefix(strings.TrimSpace(item), key+"=")
				cookies = append(cookies[:j], cookies[j+1:]...)
				exists = true
				break
			}
		}

		cookie_str := strings.Join(cookies, ";")
		if cookie_str != "" {
			newCookieHeader = append(newCookieHeader, cookie_str)
		}
	}

	if exists {
		ctx.Req.Header["Cookie"] = newCookieHeader
	}

	return
}

// Close executes the close handles.
// A HttpCtx must be closed after the request is done. It's usually done by the [Midware]
func (c *HttpCtx) Close() {
	for _, f := range c.onClose {
		f(c)
	}

	close(c.closing)
}

func (c *HttpCtx) IsClosing() <-chan struct{} {
	return c.closing
}

func (c *HttpCtx) OnClose(f func(*HttpCtx)) {
	c.onClose = append(c.onClose, f)
}

type Ret bool

const (
	RequestEnd Ret = false
	Continue   Ret = true
)

var curreq uint64

type ContentEncoding uint8

const (
	EncodingRAW ContentEncoding = iota
	EncodingBR
	EncodingGZIP
	EncodingDEFALTE
)

func (c ContentEncoding) String() string {
	switch c {
	case EncodingBR:
		return "br"
	case EncodingGZIP:
		return "gzip"
	case EncodingDEFALTE:
		return "deflate"
	case EncodingRAW:
		return "raw"
	default:
		return strconv.Itoa(int(c))
	}
}

var encoderpool = []sync.Pool{
	EncodingGZIP:    {New: func() any { return gzip.NewWriter(nil) }},
	EncodingDEFALTE: {New: func() (ret any) { ret, _ = flate.NewWriter(nil, flate.DefaultCompression); return }},
	EncodingBR:      {New: func() any { return brotli.NewWriter(nil) }},
}

func newReqID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Midware) head(rw http.ResponseWriter, r *http.Request, conn *tcp.Conn) {
	ngrw := &NgResponseWriter{
		writer:         nil,
		stdrw:          rw,
		acceptEncoding: r.Header.Get("Accept-Encoding"),
	}

	r.Header.Del("Accept-Encoding") // we don't want the backend to encode. WE DO IT.

	c, kill := context.WithCancel(r.Context())

	ip, _port, _ := gonet.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(_port)
	atomic.AddUint64(&curreq, 1)

	id := newReqID()

	ctx := &HttpCtx{
		Req:        r.WithContext(c),
		Resp:       ngrw,
		Id:         id,
		starttime:  time.Now(),
		kill:       kill,
		closing:    make(chan struct{}),
		conn:       conn,
		RemoteIP:   ip,
		RemotePort: port,
	}

	ngrw.ctx = ctx

	h.Process(ctx)
}

type NgResponseWriter struct {
	writer io.Writer
	stdrw  http.ResponseWriter

	acceptEncoding string

	code     int
	encoding ContentEncoding

	writtenBytes uint64 // before compression

	init sync.Once

	ctx *HttpCtx

	closed bool
}

func (w *NgResponseWriter) Write(b []byte) (byt int, e error) {
	w.init.Do(w.initForWrite)

	byt, e = w.writer.Write(b)
	atomic.AddUint64(&w.writtenBytes, uint64(byt))
	return
}
func (w *NgResponseWriter) WriteHeader(statusCode int) {
	if w.code == 0 {
		w.code = statusCode
		w.init.Do(w.initForWrite)

	}
}
func (w *NgResponseWriter) Header() http.Header {
	return w.stdrw.Header()
}

func (w *NgResponseWriter) BypassEncoding() {
	if w.acceptEncoding != "" {
		w.Header().Set("Accept-Encoding", w.acceptEncoding)
		w.acceptEncoding = ""
	}
}

func (w *NgResponseWriter) initForWrite() {
	w.Header().Set("Server", utils.ServerSign)
	switch w.code {
	case StatusSwitchingProtocols: // do nothing
		return
	case StatusNoContent: // no need to encode
	case 0: // no code,init to OK first
		w.code = StatusOK
		fallthrough
	default: // init encode
		if w.Header().Get("Content-Encoding") == "" &&
			w.acceptEncoding != "" { // if the content hasn't encoded,then we encode it here
			ContentLength, _ := strconv.ParseUint(w.Header().Get("Content-Length"), 10, 64)         // get the content length
			ContentType := w.Header().Get("Content-Type")                                           // get the content type
			IsDownloading := strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") // check if this request is a download action
			switch {
			case IsDownloading: // don't encode if is downloading
			// case ContentLength <= 1024: // don't encode if size too small
			case ContentLength >= 1024*1024*100: // don't encode if size too big
			case strings.HasPrefix(ContentType, "image") ||
				strings.HasPrefix(ContentType, "audio") ||
				strings.HasPrefix(ContentType, "video"): // don't encode if content type is image,audio,video
			default:
				switch { // check if we support any of the accept-encoding
				case strings.Contains(w.acceptEncoding, "br"):
					w.encoding = EncodingBR
				case strings.Contains(w.acceptEncoding, "gzip"):
					w.encoding = EncodingGZIP
				case strings.Contains(w.acceptEncoding, "deflate"):
					w.encoding = EncodingDEFALTE
				}
			}
		}
	}
	if w.encoding != EncodingRAW {
		w.Header().Add("Content-Encoding", w.encoding.String())
		w.Header().Del("Content-Length") // delete the content length that is no more correct after the encode

		_w := encoderpool[w.encoding].Get().(io.Writer) //get encoder from pool
		_w.(reSetter).Reset(w.stdrw)                    // reset the encoder
		w.writer = _w                                   // set the writer
	} else {
		w.writer = w.stdrw
	}
	// for k, v := range w.headers {
	// 	w.stdrw.Header()[k] = v // copy headers to the real writer
	// }
	w.stdrw.WriteHeader(w.code) // write the header to the real writer
}

// Close closes the writer. It must be called after the request is done.
func (w *NgResponseWriter) Close() error {
	if w.closed {
		panic("Close() called twice")
	}

	w.init.Do(w.initForWrite)

	switch w.encoding {
	case EncodingRAW: // do nothing
	default:
		w.writer.(io.Closer).Close()
		encoderpool[w.encoding].Put(w.writer)
	}

	w.closed = true
	return nil
}

func (w *NgResponseWriter) Hijack() (gonet.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.stdrw.(http.Hijacker); ok {
		w.code = http.StatusSwitchingProtocols
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker interface is not supported")
}

func (w *NgResponseWriter) Flush() {
	w.init.Do(w.initForWrite)

	if w.encoding != 0 {
		w.writer.(interface{ Flush() error }).Flush()
	}
	if fl, ok := w.stdrw.(http.Flusher); ok {
		fl.Flush()
	}
}
func (w *NgResponseWriter) Push(target string, opts *http.PushOptions) error {
	return w.stdrw.(http.Pusher).Push(target, opts)
}
func (w *NgResponseWriter) Code() int {
	return w.code
}

var _ http.Hijacker = &NgResponseWriter{}
var _ http.Flusher = &NgResponseWriter{}
var _ http.Pusher = &NgResponseWriter{}

type reSetter interface {
	Reset(io.Writer)
}
