package nghttp

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	tcpsdk "github.com/mrhaoxx/OpenNG/modules/ngtcp"
)

func init() {
	registerReverseProxier()
	registerMidware()
	registerSecureHTTP()
}

type ReverseProxierHostConfig struct {
	Name           string           `ng:"name,required" desc:"name of the proxy configuration"`
	Hosts          ng.HostnameSlice `ng:"hosts,required" desc:"hostnames to match for this proxy"`
	Backend        ngnet.URL        `ng:"backend,required" default:"sys%tcp://" desc:"backend URL to proxy requests to"`
	MaxConnsPerHost int             `ng:"MaxConnsPerHost" desc:"maximum concurrent connections per backend host"`
	TlsSkipVerify  bool             `ng:"TlsSkipVerify" desc:"skip TLS certificate verification for backend"`
	BypassEncoding bool             `ng:"BypassEncoding" desc:"bypass encoding for backend"`
}

type ReverseProxierConfig struct {
	Hosts      []ReverseProxierHostConfig `ng:"hosts" desc:"reverse proxy host configurations"`
	Allowhosts ng.HostnameSliceDefault    `ng:"allowhosts" desc:"hostnames that this proxy will handle"`
}

func NewReverseProxierFromConfig(cfg ReverseProxierConfig) (*ReverseProxy, error) {
	proxier := NewHTTPProxier(cfg.Allowhosts.GroupRegexp())

	for id, host := range cfg.Hosts {
		backend := host.Backend
		if err := proxier.Insert(id, host.Name, host.Hosts.GroupRegexp(), &backend, host.MaxConnsPerHost, host.TlsSkipVerify, host.BypassEncoding); err != nil {
			return nil, err
		}
	}

	return proxier, nil
}

func registerReverseProxier() {
	ng.RegisterFunc("http::reverseproxier", NewReverseProxierFromConfig)
}

func registerMidware() {
	ng.RegisterFunc("http::midware", NewHttpMidware)
}

func registerSecureHTTP() {
	ng.RegisterFunc("tcp::securehttp", func(struct{}) (tcpsdk.Service, error) {
		return Redirect2TLS, nil
	})
}
