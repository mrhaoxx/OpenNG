package http

import (
	"strconv"
	"strings"
	"time"

	res "github.com/haoxingxing/OpenNG/res"
	utils "github.com/haoxingxing/OpenNG/utils"

	"github.com/dlclark/regexp2"
)

const PrefixNg = "/ng-cgi"
const InternalPath = 124

func ngInternalServiceHandler(RequestCtx *HttpCtx) Ret {

	path := strings.TrimPrefix(RequestCtx.Req.URL.Path, PrefixNg)

	// ServiceWaiter := sync.WaitGroup{}

	// ReturnSigSlot := RequestCtx.Slot(InternalReturn)

	RequestCtx.Store(InternalPath, path)

	s := muxBufPath.Lookup(path).([]*shInternal)

	if len(s) == 0 {
		RequestCtx.ErrorPage(StatusNotFound, "The requested URL "+RequestCtx.Req.RequestURI+" was not found on this server.")
	}

	for _, t := range s {
		// ServiceWaiter.Add(1)
		// go func() {
		// defer ServiceWaiter.Done()

		// }()
		// for ret := range ReturnSigSlot.Wait() {
		switch t.ServiceHandler(RequestCtx) {
		case RequestEnd:
			goto _break
		case Continue:
			continue
		}
		// }
	}

_break:
	// ReturnSigSlot.Close()
	// ServiceWaiter.Wait()

	return RequestEnd
}

var mux = []*shInternal{
	{
		ServiceHandler: func(ctx *HttpCtx) Ret {
			ctx.Resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
			ctx.Resp.Header().Set("Cache-Control", "no-cache")
			ctx.WriteString("reqid: " + strconv.Itoa(int(ctx.Id)) + "\n" +
				"timestamp: " + strconv.FormatInt(time.Now().UnixMilli(), 10) + "\n" +
				"hostname: " + ctx.Req.Host + "\n" +
				"connection: " + strconv.Itoa(int(ctx.conn.Id)) + "\n" +
				"protocols: " + ctx.conn.Protocols() + "\n" +
				"remoteip: " + ctx.Req.RemoteAddr + "\n")
			return RequestEnd
		},
		paths: []*regexp2.Regexp{regexp2.MustCompile("^/trace$", regexp2.None)},
	},
	{
		ServiceHandler: func(ctx *HttpCtx) Ret {
			res.WriteLogo(ctx.Resp)
			return RequestEnd
		},
		paths: []*regexp2.Regexp{regexp2.MustCompile("^/logo$", regexp2.None)},
	},
}
var muxBufPath = utils.NewBufferedLookup(func(s string) interface{} {
	var m []*shInternal = nil
	for _, t := range mux {
		for _, r := range t.paths {
			if ok, _ := r.MatchString(s); ok {
				m = append(m, t)
			}
		}
	}
	return m
})

type shInternal struct {
	ServiceHandler
	paths []*regexp2.Regexp
}

func addInternal(s ServiceHandler, paths []*regexp2.Regexp) {
	mux = append(mux, &shInternal{
		ServiceHandler: s,
		paths:          paths,
	})
}
