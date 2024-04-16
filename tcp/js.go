package tcp

import (
	"rogchap.com/v8go"
)

type jsVM struct {
	script string
}

func (*jsVM) Handle(c *Conn) (ret SerRet) {
	iso := v8go.NewIsolate()
	ctx := v8go.NewContext(iso)

	obj := ctx.Global()
	obj.Set("ret", 0)
	ctx.RunScript("console.log('Hello, World!')", "main.js")
	_v, err := obj.Get("ret")
	if err != nil {
		return Close
	} else {
		return SerRet(_v.Uint32())
	}
	return

}
