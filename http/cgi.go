package http

import (
	"strings"
)

const PrefixNg = "/ng-cgi"

func (mid *Midware) ngCgi(RequestCtx *HttpCtx) Ret {

	path := strings.TrimPrefix(RequestCtx.Req.URL.Path, PrefixNg)

	s := mid.bufferedLookupForCgi.Lookup(path).([]*CgiStruct)

	if len(s) == 0 {
		RequestCtx.Resp.ErrorPage(StatusNotFound, "The requested URL "+RequestCtx.Req.RequestURI+"("+path+")"+" was not found on this server.")
	}

	for _, t := range s {
		switch t.CgiHandler(RequestCtx, path) {
		case RequestEnd:
			goto _break
		case Continue:
			continue
		}
	}

_break:
	return RequestEnd
}
