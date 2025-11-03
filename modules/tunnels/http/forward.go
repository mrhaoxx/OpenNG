package http

import (
	"context"
	"fmt"
	"io"
	gonet "net"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/mrhaoxx/OpenNG/pkg/groupexp"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"

	http "github.com/mrhaoxx/OpenNG/modules/http"
)

type StdForwardProxy struct {
	Underlying ngnet.Interface

	transport stdhttp.RoundTripper
	init      sync.Once
}

func (h *StdForwardProxy) HandleHTTPForward(ctx *http.HttpCtx) http.Ret {

	h.init.Do(func() {
		h.transport = &stdhttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (gonet.Conn, error) {
				return h.Underlying.Dial(network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	})

	delHopHeaders(ctx.Req.Header)

	if ctx.Req.Method == "CONNECT" {
		server, err := h.Underlying.Dial("tcp", ctx.Req.RequestURI)
		if err != nil {
			ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Forward: Dial: %v", err))
			return http.RequestEnd
		}
		defer server.Close()

		switch ctx.Req.ProtoMajor {
		case 0, 1:
			localconn, _, err := ctx.Resp.Hijack()
			if err != nil {
				ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Forward: Hijack: %v", err))
				return http.RequestEnd
			}

			defer localconn.Close()
			fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", ctx.Req.ProtoMajor, ctx.Req.ProtoMinor)

			proxy(ctx.Req.Context(), localconn, server)
		case 2:
			ctx.Resp.Header()["Date"] = nil
			ctx.Resp.WriteHeader(stdhttp.StatusOK)

			ctx.Resp.Flush()
			proxyh2(ctx.Req.Context(), ctx.Req.Body, ctx.Resp, server)
		}
	} else {
		ctx.Req.RequestURI = ""

		if ctx.Req.ProtoMajor == 2 {
			ctx.Req.URL.Scheme = "http"
			ctx.Req.URL.Host = ctx.Req.Host
		}
		resp, err := h.transport.RoundTrip(ctx.Req)

		if err != nil {
			ctx.Resp.ErrorPage(stdhttp.StatusBadRequest, fmt.Sprintf("Forward: %v", err))
			return http.RequestEnd
		}
		defer resp.Body.Close()

		copyHeader(ctx.Resp.Header(), resp.Header)
		ctx.Resp.WriteHeader(resp.StatusCode)
		flush(ctx.Resp)
		copyBody(ctx.Resp, resp.Body)
	}

	return http.RequestEnd
}

func (*StdForwardProxy) HostsForward() groupexp.GroupRegexp {
	return nil
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func delHopHeaders(header stdhttp.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func proxy(ctx context.Context, left, right ngnet.Conn) {
	wg := sync.WaitGroup{}
	cpy := func(dst, src ngnet.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}
	wg.Add(2)
	go cpy(left, right)
	go cpy(right, left)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		left.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

func proxyh2(ctx context.Context, leftreader io.ReadCloser, leftwriter io.Writer, right ngnet.Conn) {
	wg := sync.WaitGroup{}
	ltr := func(dst ngnet.Conn, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}
	rtl := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		copyBody(dst, src)
	}
	wg.Add(2)
	go ltr(right, leftreader)
	go rtl(leftwriter, right)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		leftreader.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
}

const copy_buf = 128 * 1024

func copyBody(wr io.Writer, body io.Reader) {
	buf := make([]byte, copy_buf)
	for {
		bread, read_err := body.Read(buf)
		var write_err error
		if bread > 0 {
			_, write_err = wr.Write(buf[:bread])
			flush(wr)
		}
		if read_err != nil || write_err != nil {
			break
		}
	}
}

func flush(flusher interface{}) bool {
	f, ok := flusher.(stdhttp.Flusher)
	if !ok {
		return false
	}
	f.Flush()
	return true
}

func copyHeader(dst, src stdhttp.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var _ http.Forward = (*StdForwardProxy)(nil)
