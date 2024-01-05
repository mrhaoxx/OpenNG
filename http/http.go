package http

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tcp "github.com/haoxingxing/OpenNG/tcp"
	utils "github.com/haoxingxing/OpenNG/utils"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/http2"
)

//ng:generate def obj HttpCtx
type HttpCtx struct {
	//unsync readonly
	Id        uint64
	starttime time.Time

	Req  *http.Request
	Resp *NgResponseWriter

	conn *tcp.Conn

	closing chan struct{}

	utils.StoreContext
	utils.SignalContext

	kill func()

	onClose []func(*HttpCtx)
}

// @Param int code eg. 0 -> RequestEnd; 1-> Continue; 2 -> Relocate
// @RetVal error
//
//ng:generate def func HttpCtx::Return
// func (c *HttpCtx) Return(v int) error {
// 	return c.Signal(Return, Ret(v))
// }

func (c *HttpCtx) Redirect(url string, code int) {
	http.Redirect(c.Resp, c.Req, url, code)
}

func (c *HttpCtx) WriteString(s string) {
	io.WriteString(c.Resp, s)
}

func (c *HttpCtx) SetCookie(k *http.Cookie) {
	http.SetCookie(c.Resp, k)
}
func (c *HttpCtx) Close() {
	for _, f := range c.onClose {
		f(c)
	}

	c.Resp.Close()
	c.SignalContext.Close()
	close(c.closing)
}
func (c *HttpCtx) IsClosing() <-chan struct{} {
	return c.closing
}
func (c *HttpCtx) RegCloseHandle(f func(*HttpCtx)) {
	c.onClose = append(c.onClose, f)
}

var h2s = &http2.Server{}

type Ret bool
type ServiceHandler func(*HttpCtx) Ret

const (
	RequestEnd Ret = false
	Continue   Ret = true

	Killsig uint8 = 1
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

func (h *Midware) head(rw http.ResponseWriter, r *http.Request, conn *tcp.Conn) {
	ngrw := &NgResponseWriter{
		writer:         nil,
		stdrw:          rw,
		acceptEncoding: r.Header.Get("Accept-Encoding"),
	}

	r.Header.Del("Accept-Encoding")

	c, kill := context.WithCancel(r.Context())

	ctx := &HttpCtx{
		Req:       r.WithContext(c),
		Resp:      ngrw,
		Id:        (atomic.AddUint64(&curreq, 1)),
		starttime: time.Now(),
		kill:      kill,
		closing:   make(chan struct{}),
		conn:      conn,
	}
	n := strings.Split(r.Host, ".")
	if len(n) >= 2 {
		rawh := strings.Join(n[len(n)-2:], ".")
		ctx.Store(Mainhost, rawh)
		n = strings.Split(rawh, ":")
		ctx.Store(Maindomain, n[0])
	} else {
		ctx.Store(Mainhost, r.Host)
		ctx.Store(Maindomain, r.Host)
	}
	h.Process(ctx)
}

const (
	Mainhost = iota + 100
	Maindomain
)

type NgResponseWriter struct {
	writer io.Writer
	stdrw  http.ResponseWriter

	acceptEncoding string

	code     int
	encoding ContentEncoding

	writtenBytes uint64

	init sync.Once
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
func (w *NgResponseWriter) Close() error {
	w.init.Do(w.initForWrite)

	switch w.encoding {
	case EncodingRAW: // do nothing
	case EncodingBR:
		w.writer.(*brotli.Writer).Close()
	default:
		w.writer.(io.Closer).Close()
		encoderpool[w.encoding].Put(w.writer)
	}
	return nil
}
func (w *NgResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.stdrw.(http.Hijacker); ok {
		w.code = http.StatusSwitchingProtocols
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker interface is not supported")
}

type NgFlusher interface {
	Flush() error
}

func (w *NgResponseWriter) Flush() {
	w.init.Do(w.initForWrite)

	if w.encoding != 0 {
		w.writer.(NgFlusher).Flush()
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
