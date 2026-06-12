package nghttp

func (h *Midware) ngForwardProxy(ctx *HttpCtx) {

	ServicesToExecute := h.bufferedLookupForForward.Lookup(ctx.Req.Host)
	for i := 0; i < len(ServicesToExecute); i++ {

		ctx.tracePath(ServicesToExecute[i].Id + " ")
		switch ServicesToExecute[i].ServiceHandler(ctx) {
		case RequestEnd:
			return
		case Continue:
			continue
		}
	}

}
