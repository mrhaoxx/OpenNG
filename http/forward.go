package http

func (h *Midware) ngForwardProxy(ctx *HttpCtx, RequestPath *string) {

	ServicesToExecute := h.bufferedLookupForForward.Lookup(ctx.Req.Host)
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
