package ui

import (
	"errors"
	"os"
	"strconv"
	"strings"

	auth "github.com/haoxingxing/OpenNG/auth"
	http "github.com/haoxingxing/OpenNG/http"
	logging "github.com/haoxingxing/OpenNG/logging"
	tcp "github.com/haoxingxing/OpenNG/tcp"
	tls "github.com/haoxingxing/OpenNG/tls"

	"gopkg.in/yaml.v3"
)

type Cfg struct {
	Version int
	Auth    auth.Config          `yaml:"Auth,flow"`
	TCP     tcp.Config           `yaml:"TCP,flow"`
	TLS     tls.Config           `yaml:"TLS,flow"`
	HTTP    http.Config          `yaml:"HTTP,flow"`
	Logger  logging.LoggerConfig `yaml:"Logger,flow"`
}

var TcpController = tcp.Controller{
	Services: map[string]tcp.ServiceHandler{
		"tls":     TlsMgr,
		"knock":   Knock,
		"proxier": TcpProxier,
		"pph":     tcp.NewTCPProxyProtocolHandler(),
		"rdtls":   http.NewTCPRedirectToTls(),
		"http":    HttpMidware,
		"det": &tcp.Detect{Dets: []tcp.Detector{
			tcp.DetectTLS,
			tcp.DetectPROXYPROTOCOL,
			tcp.DetectSSH,
			tcp.DetectRDP,
			tcp.DetectHTTP,
		}},
	},
	Binds: map[string][]tcp.SericeBinding{},
}

var HttpMidware = http.NewHttpMidware([]string{"*"})

var HttpProxier = http.NewHTTPProxier()

var TcpProxier = tcp.NewTcpProxier()

var TlsMgr = tls.NewTlsMgr()

var pba = auth.NewPBAuth()
var Auth = auth.NewAuthMgr([]auth.AuthHandle{pba})

var Knock = auth.NewKnockMgr()

func init() {
	HttpMidware.AddService("Proxier", HttpProxier)
	HttpMidware.AddService("Auth", Auth)
	HttpMidware.AddService("Knock", Knock)
	HttpMidware.AddService("InPx", http.NewInternalProxier())
	HttpMidware.AddService("NgUI", &UI{})

	HttpMidware.AddServiceInternal(pba)
	HttpMidware.AddServiceInternal(HttpProxier)
}
func LoadCfg(cfgs []byte) error {
	var cfg Cfg

	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}
	if cfg.Version != 4 {
		return errors.New("Configuration version not met. Require 4. Got " + strconv.Itoa(cfg.Version) + ".")
	}
	curcfg = cfgs

	//Preprocess Turn all reference to real value
	ref := map[string][]string{}
	//create a map for reference
	for _, host := range cfg.HTTP.Proxier.Hosts {
		ref[host.Name] = host.Hosts
	}

	for i, policy := range cfg.Auth.Policies {
		var real_hosts []string
		for _, host := range policy.Hosts {
			if strings.HasPrefix(host, "$") {
				real_hosts = append(real_hosts, ref[host[1:]]...)
			} else {
				real_hosts = append(real_hosts, host)
			}
		}
		cfg.Auth.Policies[i].Hosts = real_hosts
	}

	logging.Load(cfg.Logger)
	if cfg.Logger.EnableSSE {
		logging.RegisterLogger(Sselogger)
		logging.Println("sys", "SSE Logger Registered")
	}
	err = pba.Load(cfg.Auth)
	if err != nil {
		logging.Println("sys", "auth", err)
		os.Exit(-1)
	}
	err = TcpController.InitAndLoad(cfg.TCP.Controller)
	if err != nil {
		logging.Println("sys", "tcp", err)
		os.Exit(-1)
	}
	err = HttpMidware.Load(cfg.HTTP.Midware)
	if err != nil {
		logging.Println("sys", "http", err)
		os.Exit(-1)
	}
	err = HttpProxier.Load(cfg.HTTP.Proxier, true)
	if err != nil {
		logging.Println("sys", "httpproxy", err)
		os.Exit(-1)
	}
	err = TcpProxier.Load(cfg.TCP.Proxier, true)
	if err != nil {
		logging.Println("sys", "tcpproxy", err)
		os.Exit(-1)
	}
	TlsMgr.Load(cfg.TLS)

	return nil
}
