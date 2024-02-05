package ui

import (
	"errors"
	"os"
	"strconv"
	"strings"

	auth "github.com/mrhaoxx/OpenNG/auth"
	http "github.com/mrhaoxx/OpenNG/http"
	logging "github.com/mrhaoxx/OpenNG/log"
	tcp "github.com/mrhaoxx/OpenNG/tcp"
	tls "github.com/mrhaoxx/OpenNG/tls"

	"gopkg.in/yaml.v3"
)

type Cfg struct {
	Version int
	Auth    authConfig `yaml:"Auth,flow"`
	TCP     tcpConfig  `yaml:"TCP,flow"`
	TLS     tlsConfig  `yaml:"TLS,flow"`
	HTTP    httpConfig `yaml:"HTTP,flow"`
	Logger  logConfig  `yaml:"Logger,flow"`
}

var TcpController = tcp.NewTcpController(map[string]tcp.ServiceHandler{
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
})
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

	if cfg.Logger.DisableConsole {
		logging.Println("sys", "Disabling Console Logging")
		logging.ClearLoggers()
	}

	if cfg.Logger.File != "" {
		f, _ := os.OpenFile(cfg.Logger.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		logging.RegisterLogger(f)
		logging.Println("sys", "File Logger Registered", cfg.Logger.File)
	}

	if cfg.Logger.UDP.Address != "" {
		logging.RegisterLogger(NewUdpLogger(cfg.Logger.UDP.Address))
		logging.Println("sys", "UDP Logger Registered", cfg.Logger.UDP.Address)
	}

	if cfg.Logger.EnableSSE {
		logging.RegisterLogger(Sselogger)
		logging.Println("sys", "SSE Logger Registered")
	}

	for _, u := range cfg.Auth.Users {
		logging.Println("sys", "auth", "Found User", u.Username)
		pba.SetUser(u.Username, u.PasswordHash)
	}
	for _, p := range cfg.Auth.Policies {
		logging.Println("sys", "auth", "Found Policy", p.Name)
		if err = pba.AddPolicy(p.Name, p.Allowance, p.Users, p.Hosts, p.Paths); err != nil {
			break
		}
	}

	if err != nil {
		logging.Println("sys", "auth", err)
		os.Exit(-1)
	}

	for _, bind := range cfg.HTTP.Midware.Binds {
		logging.Println("sys", "http", "Binding", bind.Id)
		HttpMidware.Bind(bind.Id, bind.Name, bind.Hosts)
	}

	if err != nil {
		logging.Println("sys", "http", err)
		os.Exit(-1)
	}

	for _, host := range cfg.HTTP.Proxier.Hosts {
		logging.Println("sys", "httpproxy", host.Name, host.Hosts)
		if err := HttpProxier.Add(host.Name, host.Hosts, host.Backend, 0, host.TlsSkipVerify); err != nil {
			break
		}
	}
	if err != nil {
		logging.Println("sys", "httpproxy", err)
		os.Exit(-1)
	}

	for _, e := range cfg.TCP.Proxier.Routes {
		logging.Println("sys", "tcpproxy", e.Name, e.Protocol, "->", e.Backend)

		if err := TcpProxier.Add(e.Name, e.Backend, e.Protocol); err != nil {
			return nil
		}
	}
	if err != nil {
		logging.Println("sys", "tcpproxy", err)
		os.Exit(-1)
	}

	for _, c := range cfg.TLS.Certificates {
		logging.Println("sys", "tls", "Found certificate", c.CertFile)

		err = TlsMgr.LoadCertificate(c.CertFile, c.KeyFile)
	}

	if err != nil {
		logging.Println("sys", "tls", err)
		os.Exit(-1)
	}

	for protocol, bindings := range cfg.TCP.Controller.Binds {
		logging.Println("sys", "tcp", "Services Bindings", protocol, "->", bindings)
		if err = TcpController.Bind(protocol, bindings); err != nil {
			break
		}
	}

	if err != nil {
		logging.Println("sys", "tcp", err)
		os.Exit(-1)
	}

	for _, bds := range cfg.TCP.Controller.AddressBindings {
		logging.Println("sys", "tcp", "Listening on", bds)
		if err := TcpController.Listen(bds); err != nil {
			break
		}
	}
	if err != nil {
		logging.Println("sys", "tcp", err)
		os.Exit(-1)
	}

	return nil
}
