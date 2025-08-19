package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	gonet "net"

	"github.com/mrhaoxx/OpenNG/net"
	"github.com/mrhaoxx/OpenNG/utils"
)

func (h *Midware) ngForwardProxy(ctx *HttpCtx, RequestPath *string) {

	ServicesToExecute := h.bufferedLookupForForward.Lookup(ctx.Req.Host).([]*ServiceStruct)
	for i := 0; i < len(ServicesToExecute); i++ {

		*RequestPath += ServicesToExecute[i].Id + " "
		switch ServicesToExecute[i].ServiceHandler(ctx) {
		case RequestEnd:
			*RequestPath += "-"
			return
		case Continue:
			continue
		}
	}

}

type StdForwardProxy struct {
	Underlying net.Interface

	transport http.RoundTripper
	init      sync.Once
}

func (h *StdForwardProxy) HandleHTTPForward(ctx *HttpCtx) Ret {

	h.init.Do(func() {
		if h.Underlying == nil {
			h.Underlying = net.DefaultRouteTable
		}

		h.transport = &http.Transport{
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
			return RequestEnd
		}
		defer server.Close()

		switch ctx.Req.ProtoMajor {
		case 0, 1:
			localconn, _, err := ctx.Resp.Hijack()
			if err != nil {
				ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Forward: Hijack: %v", err))
				return RequestEnd
			}

			defer localconn.Close()
			fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", ctx.Req.ProtoMajor, ctx.Req.ProtoMinor)

			proxy(ctx.Req.Context(), localconn, server)
		case 2:
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
		resp, err := h.transport.RoundTrip(ctx.Req)

		if err != nil {
			ctx.Resp.ErrorPage(http.StatusBadRequest, fmt.Sprintf("Forward: %v", err))
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

func (*StdForwardProxy) HostsForward() utils.GroupRegexp {
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
