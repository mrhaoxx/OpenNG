package http

import "fmt"

func EchoVerbose(ctx *HttpCtx) Ret {
	ctx.WriteString("Method: " + ctx.Req.Method + "\n")
	ctx.WriteString("URL: " + ctx.Req.URL.String() + "\n")
	ctx.WriteString("Proto: " + ctx.Req.Proto + "\n")
	ctx.WriteString("Host: " + ctx.Req.Host + "\n")
	ctx.WriteString("RemoteAddr: " + ctx.Req.RemoteAddr + "\n")
	ctx.WriteString("RequestURI: " + ctx.Req.RequestURI + "\n")

	for name, values := range ctx.Req.Header {
		for _, value := range values {
			fmt.Fprintf(ctx.Resp, "%v: %v\n", name, value)
		}
	}

	return RequestEnd
}
