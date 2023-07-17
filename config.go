package main

import (
	_ "embed"
	_ "net/http/pprof"
)

var gitver = "dev"
var buildstamp = "dev-built"

// //ng:generate def func restart
// func restart() error {
// 	reload.Exec()
// 	return nil
// }

// // @RetVal string version
// //
// //ng:generate def func version
// func version() string {
// 	return gitver + " " + buildstamp + " " + runtime.Version() + " " + runtime.GOARCH + " " + runtime.GOOS
// }

// //ng:generate def func setlogfile
// //@Param string logfile path to log file
// //@RetVal error
// func setlogfile(logfile string) error {
// 	f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
// 	if err != nil {
// 		return err
// 	}
// 	log.SetOutput(io.MultiWriter(sseLogger, f))
// 	return nil
// }

// @RetVal string uptime
//
//ng:generate def func uptime
// func uptime() string {
// 	return time.Since(up).String()
// }

// // @OptionalParam int=0 timeout seconds. 0 means no timeout
// //
// //ng:generate def func wait
// func wait(sec int) error {
// 	if sec == 0 {
// 		<-make(chan struct{})
// 	} else {
// 		time.Sleep(time.Duration(sec) * time.Second)
// 	}
// 	return nil
// }

// loadcfg(cfg string)
// func loadcfg(args cmd.Data, ret *cmd.RetCtx) {
// 	args.Require(cmd.TYPE_STRING)
// 	// cfg, e := base64.StdEncoding.DecodeString(args[0].(string))
// 	// if e != nil {
// 	// 	ret.SetStatus(cmd.StatusERR).SetData(cmd.Data{e.Error()}).Commit()
// 	// 	return
// 	// }
// 	cfg := []byte(args[0].(string))

// 	d := Config{}
// 	curcfg = cfg
// 	e := yaml.UnmarshalStrict(cfg, &d)
// 	if e != nil {
// 		ret.SetStatus(cmd.StatusERR).SetData(cmd.Data{e.Error()}).Commit()
// 		return
// 	} else {
// 		parseCfg(d)
// 	}
// 	ret.SetStatus(cmd.StatusOK).Commit()
// }

// // reload()
// func _reload(args cmd.Data, ret *cmd.RetCtx) {
// 	args.Require()
// 	curcfg, _ = ioutil.ReadFile("config.yaml")
// 	d = Config{}
// 	e := yaml.UnmarshalStrict(curcfg, &d)
// 	if e != nil {
// 		ret.SetStatus(cmd.StatusERR).SetData(cmd.Data{e.Error()}).Commit()
// 		return
// 	} else {
// 		parseCfg(d)
// 	}
// 	ret.SetStatus(cmd.StatusOK).Commit()
// }

// // getcfg()
// func getcfg(args cmd.Data, ret *cmd.RetCtx) {
// 	args.Require()
// 	ret.SetStatus(cmd.StatusOK).SetData(cmd.Data{string(curCfg)}).Commit()
// }

// // savecfg(cfg string)
// func savecfg(args cmd.Data, ret *cmd.RetCtx) {
// 	args.Require(cmd.TYPE_STRING)
// 	ioutil.WriteFile(cfgfile, []byte(args[0].(string)), fs.ModeCharDevice)
// 	ret.SetStatus(cmd.StatusOK).Commit()
// }

// func NewNetGATEManageInterface() (error, interface{}) {
// 	return nil, http.NewServiceHolder([]*regexp2.Regexp{},
// 		func(ctx *http.HttpCtx) {
// 			switch ctx.Req.URL.Path {
// 			case "/ng-cgi/trace":
// 				ctx.WriteString("apiversion: " + utils.APIVERSION + "\n")
// 				ctx.Signal(http.Return, http.RequestEnd)
// 				return
// 			// case "/cmd/post":
// 			// 	ctx.Resp.Header().Set("Cache-Control", "no-cache")
// 			// 	ctx.Req.ParseForm()
// 			// 	form := ctx.Req.PostForm
// 			// 	// ret := cmd.Parse(form.Get("cmd")).Execute()
// 			// 	bytes, _ := json.Marshal(map[string]interface{}{
// 			// 		"status": ret.Wait().Status(),
// 			// 		"data":   ret.Data(),
// 			// 	})
// 			// 	ctx.WriteString(string(bytes))
// 			// case "/cmd/ws":
// 			// 	websocket.Handler(func(ws *websocket.Conn) {
// 			// 		defer ws.Close()
// 			// 		closing := false
// 			// 		go func() {
// 			// 			slt := ctx.Slot(http.Return)
// 			// 			<-slt.Wait()
// 			// 			closing = true
// 			// 		}()
// 			// 		indexed := false
// 			// 		for !closing {
// 			// 			var msg string

// 			// 			err := websocket.Message.Receive(ws, &msg)

// 			// 			if err != nil {
// 			// 				break
// 			// 			}
// 			// 			switch msg {
// 			// 			case "ping":
// 			// 				websocket.Message.Send(ws, "pong")
// 			// 			case "index":
// 			// 				indexed = true
// 			// 			default:
// 			// 				var ret cmd.RetInterface
// 			// 				var t string
// 			// 				if indexed {
// 			// 					_t := strings.Split(msg, " ")
// 			// 					t = _t[0]
// 			// 					ret = cmd.Parse(strings.Join(_t[1:], " ")).Execute()
// 			// 				} else {
// 			// 					ret = cmd.Parse(msg).Execute()
// 			// 				}
// 			// 				if indexed {
// 			// 					go func() {
// 			// 						bytes, _ := json.Marshal(map[string]interface{}{
// 			// 							"status": ret.Wait().Status(),
// 			// 							"data":   ret.Data(),
// 			// 							"index":  t,
// 			// 						})
// 			// 						websocket.Message.Send(ws, string(bytes))
// 			// 					}()
// 			// 				} else {
// 			// 					bytes, _ := json.Marshal(map[string]interface{}{
// 			// 						"status": ret.Wait().Status(),
// 			// 						"data":   ret.Data(),
// 			// 					})
// 			// 					websocket.Message.Send(ws, string(bytes))
// 			// 				}
// 			// 			}
// 			// 		}
// 			// 	}).ServeHTTP(ctx.Resp, ctx.Req)
// 			default:
// 				if strings.HasPrefix(ctx.Req.URL.Path, "/debug/pprof") {
// 					stdhttp.DefaultServeMux.ServeHTTP(ctx.Resp, ctx.Req)
// 				} else {
// 					ctx.Resp.WriteHeader(http.StatusNotFound)
// 				}
// 			}
// 			ctx.Signal(http.Return, http.RequestEnd)
// 		})
// }

// func initknockmgr(args cmd.Data, ret *cmd.RetCtx) {
// 	args.Require(cmd.TYPE_STRING, cmd.TYPE_STRING, cmd.TYPE_STRING, cmd.TYPE_STRING, cmd.TYPE_STRING, cmd.TYPE_STRING)
// 	knockmgr := cmd.GLOBAL.Get(args[0].(string)).(*auth.KnockMgr)
// 	midware := cmd.GLOBAL.Get(args[1].(string)).(*http.Midware)

// //go:embed doc.md
// var doc string
