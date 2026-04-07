package http

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

type ProxyConfig struct {
	URL ngnet.URL `ng:"url,required" default:"sys%"`
}

func NewProxy(cfg ProxyConfig) (*HttpProxyInterface, error) {
	u := cfg.URL
	return &HttpProxyInterface{Proxyurl: &u}, nil
}

type ForwardProxierConfig struct {
	Interface ngnet.Interface `ng:"interface" default:"sys"`
}

func NewForwardProxier(cfg ForwardProxierConfig) (*StdForwardProxy, error) {
	return &StdForwardProxy{Underlying: cfg.Interface}, nil
}

func init() {
	ng.RegisterFunc("http::proxy", NewProxy)
	ng.RegisterFunc("http::forwardproxier", NewForwardProxier)
}
