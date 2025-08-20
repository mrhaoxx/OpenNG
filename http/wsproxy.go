package http

// From https://github.com/koding/websocketproxy/blob/master/websocketproxy.go

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

type WebsocketProxy struct {
	Backend func(*http.Request) *url.URL

	Dialer *websocket.Dialer
}

func NewWSProxy(target *url.URL) *WebsocketProxy {
	backend := func(r *http.Request) *url.URL {
		// Shallow copy
		u := *target
		u.Fragment = r.URL.Fragment
		u.Path = r.URL.Path
		u.RawQuery = r.URL.RawQuery
		return &u
	}
	return &WebsocketProxy{Backend: backend}
}

var defaultUpgrader = &websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (w *WebsocketProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	backendURL := w.Backend(req)

	dialer := w.Dialer

	requestHeader := req.Header.Clone()

	requestHeader.Del("Connection")
	requestHeader.Del("Sec-Websocket-Extensions")
	requestHeader.Del("Sec-Websocket-Key")
	requestHeader.Del("Sec-Websocket-Version")
	requestHeader.Del("Upgrade")

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		requestHeader.Set("X-Forwarded-For", clientIP)
	}

	requestHeader.Add("X-Forwarded-Host", req.Host)

	if req.TLS != nil {
		requestHeader.Set("X-Forwarded-Proto", "https")
	} else {
		requestHeader.Set("X-Forwarded-Proto", "http")
	}

	connBackend, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		if resp != nil {
			copyResponse(rw, resp)
		} else {
			rw.(*NgResponseWriter).ErrorPage(http.StatusBadGateway, "Bad Gateway\n"+strconv.Quote(err.Error()))
		}
		return
	}
	defer connBackend.Close()

	upgrader := defaultUpgrader

	// Only pass those headers to the upgrader.
	upgradeHeader := http.Header{}
	if hdr := resp.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := resp.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}

	// Now upgrade the existing incoming request to a WebSocket connection.
	// Also pass the header that we gathered from the Dial handshake.
	connPub, err := upgrader.Upgrade(rw, req, upgradeHeader)
	if err != nil {
		log.Printf("websocketproxy: couldn't upgrade %s", err)
		return
	}
	defer connPub.Close()

	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)
	replicateWebsocketConn := func(dst, src *websocket.Conn, errc chan error) {
		for {
			msgType, msg, err := src.ReadMessage()
			if err != nil {
				m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", err))
				if e, ok := err.(*websocket.CloseError); ok {
					if e.Code != websocket.CloseNoStatusReceived {
						m = websocket.FormatCloseMessage(e.Code, e.Text)
					}
				}
				errc <- err
				dst.WriteMessage(websocket.CloseMessage, m)
				break
			}
			err = dst.WriteMessage(msgType, msg)
			if err != nil {
				errc <- err
				break
			}
		}
	}
	connPub.SetPingHandler(func(appData string) error {
		err := connBackend.WriteControl(websocket.PingMessage, []byte(appData), time.Now().Add(time.Second))
		if err != nil {
			return err
		}

		// default behavior from https://github.com/gorilla/websocket/blob/v1.5.0/conn.go#L1161-L1167
		err = connPub.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		} else if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}
		return err
	})

	go replicateWebsocketConn(connPub, connBackend, errClient)
	go replicateWebsocketConn(connBackend, connPub, errBackend)

	var message string
	select {
	case err = <-errClient:
		message = "websocketproxy: Error when copying from backend to client: %v"
	case err = <-errBackend:
		message = "websocketproxy: Error when copying from client to backend: %v"

	}
	if e, ok := err.(*websocket.CloseError); !ok || e.Code == websocket.CloseAbnormalClosure {
		log.Printf(message, err)
	}
}
