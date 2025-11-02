package http

import (
	"strings"
)

const PrefixNg = "/ng-cgi"

func (mid *Midware) ngCgi(RequestCtx *HttpCtx, RequestPath *string) {

	path := strings.TrimPrefix(RequestCtx.Req.URL.Path, PrefixNg)

	s := mid.bufferedLookupForCgi.Lookup(path)

	if len(s) == 0 {
		RequestCtx.Resp.ErrorPage(StatusNotFound, "The requested URL "+RequestCtx.Req.RequestURI+" was not found on this server.")
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
	*RequestPath += "-"

}
