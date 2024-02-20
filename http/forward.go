package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

func (h *Midware) ngForwardProxy(ctx *HttpCtx) Ret {
	if h.proxychan != nil {
		for _, v := range h.proxychan {
			switch v(ctx) {
			case RequestEnd:
				return RequestEnd
			case Continue:
				continue
			}
		}
	}

	return RequestEnd
}

func (h *Midware) AddForwardProxiers(p ...ServiceHandler) {
	h.proxychan = append(h.proxychan, p...)
}

func StdForwardProxy(ctx *HttpCtx) Ret {
	delHopHeaders(ctx.Req.Header)

	if ctx.Req.Method == "CONNECT" {
		server, err := net.Dial("tcp", ctx.Req.RequestURI)
		if err != nil {
			ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Dial: %v", err))
			return RequestEnd
		}
		defer server.Close()

		if ctx.Req.ProtoMajor == 0 || ctx.Req.ProtoMajor == 1 {
			localconn, _, err := ctx.Resp.Hijack()
			if err != nil {
				ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Hijack: %v", err))
				return RequestEnd
			}

			defer localconn.Close()
			fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", ctx.Req.ProtoMajor, ctx.Req.ProtoMinor)

			proxy(ctx.Req.Context(), localconn, server)
		} else if ctx.Req.ProtoMajor == 2 {
			ctx.Resp.Header()["Date"] = nil
			ctx.Resp.WriteHeader(http.StatusOK)

			ctx.Resp.Flush()
			proxyh2(ctx.Req.Context(), ctx.Req.Body, ctx.Resp, server)
		}
	} else {
		ctx.Req.RequestURI = ""
		if ctx.Req.ProtoMajor == 2 {
			ctx.Req.URL.Scheme = "http"
			ctx.Req.URL.Host = ctx.Req.Host
		}
		resp, err := http.DefaultTransport.RoundTrip(ctx.Req)

		if err != nil {
			ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("%v", err))
			return RequestEnd
		}
		defer resp.Body.Close()

		copyHeader(ctx.Resp.Header(), resp.Header)
		ctx.Resp.WriteHeader(resp.StatusCode)
		flush(ctx.Resp)
		copyBody(ctx.Resp, resp.Body)
	}

	return RequestEnd
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

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func proxy(ctx context.Context, left, right net.Conn) {
	wg := sync.WaitGroup{}
	cpy := func(dst, src net.Conn) {
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

func proxyh2(ctx context.Context, leftreader io.ReadCloser, leftwriter io.Writer, right net.Conn) {
	wg := sync.WaitGroup{}
	ltr := func(dst net.Conn, src io.Reader) {
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

const COPY_BUF = 128 * 1024

func copyBody(wr io.Writer, body io.Reader) {
	buf := make([]byte, COPY_BUF)
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
	f, ok := flusher.(http.Flusher)
	if !ok {
		return false
	}
	f.Flush()
	return true
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
