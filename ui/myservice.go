package ui

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/auth"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/tls"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

var TcpController = tcp.NewTcpController(map[string]tcp.ServiceHandler{
	"tls":     TlsMgr,
	"knock":   Knock,
	"proxier": TcpProxier,
	"pph":     tcp.NewTCPProxyProtocolHandler(),
	"rdtls":   http.Redirect2TLS,
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
	// HttpMidware.AddService("dump", http.NewServiceHolder([]*regexp2.Regexp{regexp2.MustCompile(".*", regexp2.None)}, http.EchoVerbose, nil, nil))
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
		log.Println("sys", "Disabling Console Logging")
		log.ClearLoggers()
	}

	if cfg.Logger.File != "" {
		f, _ := os.OpenFile(cfg.Logger.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		log.RegisterLogger(f)
		log.Println("sys", "File Logger Registered", cfg.Logger.File)
	}

	if cfg.Logger.UDP.Address != "" {
		log.RegisterLogger(NewUdpLogger(cfg.Logger.UDP.Address))
		log.Println("sys", "UDP Logger Registered", cfg.Logger.UDP.Address)
	}

	if cfg.Logger.EnableSSE {
		log.RegisterLogger(Sselogger)
		log.Println("sys", "SSE Logger Registered")
	}

	for _, u := range cfg.Auth.Users {
		log.Println("sys", "auth", "Found User", u.Username)
		pba.SetUser(u.Username, u.PasswordHash)
	}
	for _, p := range cfg.Auth.Policies {
		log.Println("sys", "auth", "Found Policy", p.Name)
		if err = pba.AddPolicy(p.Name, p.Allowance, p.Users, p.Hosts, p.Paths); err != nil {
			break
		}
	}

	if err != nil {
		log.Println("sys", "auth", err)
		os.Exit(-1)
	}

	for _, bind := range cfg.HTTP.Midware.Binds {
		log.Println("sys", "http", "Binding", bind.Id)
		err = HttpMidware.Bind(bind.Id, bind.Name, bind.Hosts)
		if err != nil {
			break
		}
	}

	if err != nil {
		log.Println("sys", "http", err)
		os.Exit(-1)
	}

	for _, host := range cfg.HTTP.Proxier.Hosts {
		log.Println("sys", "httpproxy", host.Name, host.Hosts)
		if err := HttpProxier.Add(host.Name, host.Hosts, host.Backend, 0, host.TlsSkipVerify); err != nil {
			break
		}
	}
	if err != nil {
		log.Println("sys", "httpproxy", err)
		os.Exit(-1)
	}

	for _, e := range cfg.TCP.Proxier.Routes {
		log.Println("sys", "tcpproxy", e.Name, e.Protocol, "->", e.Backend)

		if err := TcpProxier.Add(e.Name, e.Backend, e.Protocol); err != nil {
			return nil
		}
	}
	if err != nil {
		log.Println("sys", "tcpproxy", err)
		os.Exit(-1)
	}

	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		log.Println("sys", "tls", "watch", err)
	} else {
		go func() {
			var lastReload = time.Now()
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					if event.Has(fsnotify.Write) {
						if lastReload.Add(5 * time.Second).After(time.Now()) {
							continue
						}
						lastReload = time.Now()
						log.Println("sys", "tls", "watch", "modified", event.Name)
						time.Sleep(2 * time.Second)
						TlsMgr.ResetCertificates()

						for _, c := range cfg.TLS.Certificates {
							log.Println("sys", "tls", "Reload certificate", c.CertFile)
							TlsMgr.LoadCertificate(c.CertFile, c.KeyFile)
						}
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Println("sys", "tls", "watch", err)
				}
			}
		}()
	}

	for _, c := range cfg.TLS.Certificates {
		log.Println("sys", "tls", "Found certificate", c.CertFile)

		err = TlsMgr.LoadCertificate(c.CertFile, c.KeyFile)
		if err != nil {
			break
		}
		if watcher != nil {
			err = watcher.Add(c.CertFile)
			if err != nil {
				log.Println("sys", "tls", "watch", "failed to watch:", c.CertFile, err)
			} else {
				log.Println("sys", "tls", "watch", c.CertFile)
			}
		}
	}

	if err != nil {
		log.Println("sys", "tls", err)
		os.Exit(-1)
	}

	for protocol, bindings := range cfg.TCP.Controller.Binds {
		log.Println("sys", "tcp", "Services Bindings", protocol, "->", bindings)
		if err = TcpController.Bind(protocol, bindings); err != nil {
			break
		}
	}

	if err != nil {
		log.Println("sys", "tcp", err)
		os.Exit(-1)
	}

	for _, bds := range cfg.TCP.Controller.AddressBindings {
		log.Println("sys", "tcp", "Listening on", bds)
		if err := TcpController.Listen(bds); err != nil {
			break
		}
	}
	if err != nil {
		log.Println("sys", "tcp", err)
		os.Exit(-1)
	}
	var Dns = dns.NewServer(cfg.DNS.Domain)
	log.Println("sys", "dns", "domain is", cfg.DNS.Domain)
	for _, f := range cfg.DNS.Filters {
		log.Println("sys", "dns", "Filter", f.Name, f.Allowance)
		r, err := regexp2.Compile(dns.Dnsname2Regexp(f.Name), 0)
		if err != nil {
			log.Println("sys", "dns", err)
			os.Exit(-1)
		}
		Dns.AddFilter(r, f.Allowance)
	}
	for _, r := range cfg.DNS.Records {
		log.Println("sys", "dns", "Record", r.Domain, r.Type, r.Value)
		Dns.AddRecord(regexp2.MustCompile(dns.Dnsname2Regexp(r.Domain), 0), dns.DnsStringTypeToInt(r.Type), r.Value)
	}
	for _, b := range cfg.DNS.Binds {
		log.Println("sys", "dns", b.Name, "->", b.Addr)
		err := Dns.AddRecordWithIP(b.Name, b.Addr)
		if err != nil {
			log.Println("sys", "dns", err)
			os.Exit(-1)
		}
	}

	if cfg.DNS.Bind != "" {
		go func() {
			log.Println("sys", "dns", "starting server at", cfg.DNS.Bind)
			err := Dns.Listen(cfg.DNS.Bind)
			if err != nil {
				log.Println("sys", "dns", err)
			}
		}()
	}

	return nil
}

func NewUdpLogger(address string) *udpLogger {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}
	return &udpLogger{UDPConn: conn}
}

type udpLogger struct {
	*net.UDPConn
}
