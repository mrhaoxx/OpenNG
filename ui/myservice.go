package ui

import (
	"errors"
	"net"
	stdhttp "net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/auth"
	authbackends "github.com/mrhaoxx/OpenNG/auth/backend"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/ssh"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/tls"
	"github.com/mrhaoxx/OpenNG/utils"
	gossh "golang.org/x/crypto/ssh"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

var TcpController = tcp.NewTcpController()
var HttpMidware = http.NewHttpMidware([]string{"*"})

var HttpProxier = http.NewHTTPProxier()

var TcpProxier = tcp.NewTcpProxier()

var TlsMgr = tls.NewTlsMgr()

var pba = auth.NewPBAuth()
var Auth = auth.NewAuthMgr([]auth.AuthHandle{pba}, utils.GroupRegexp{regexp2.MustCompile("^.*$", 0)})

var Dns = dns.NewServer()

var Knock = auth.NewKnockMgr()

var builtinForwardProxiers = map[string]http.ServiceHandler{
	"Auth":       pba.HandleProxy,
	"StdProxier": http.StdForwardProxy,
}

var builtinHttpServices = map[string]http.Service{
	"Proxier": HttpProxier,
	"Auth":    Auth,
	"Knock":   Knock,
	"NgUI":    &UI{},
}

type AcmeWebRoot struct {
	AllowedHosts []string
	WWWRoot      string
}

func (a *AcmeWebRoot) Handle(conn *tcp.Conn) tcp.SerRet {
	_req, ok := conn.Load(tcp.KeyHTTPRequest)
	if !ok {
		return tcp.Continue
	}

	req, ok := _req.(*stdhttp.Request)

	if !ok {
		return tcp.Continue
	}

	if !strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		return tcp.Continue
	}
	for _, h := range a.AllowedHosts {
		if req.Host == h {
			goto allowed
		}
	}
	return tcp.Continue

allowed:
	s := stdhttp.FileServer(stdhttp.Dir(a.WWWRoot))
	stdhttp.Serve(utils.ConnGetSocket(conn.TopConn()), stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.ServeHTTP(w, r)
	}))
	return tcp.Close

}

type SniAndipFilter struct {
	AllowedSNI []string
	ipf        tcp.ServiceHandler
}

func (s *SniAndipFilter) Handle(conn *tcp.Conn) tcp.SerRet {
	_req, ok := conn.Load(tcp.KeyTlsSni)
	if !ok {
		return tcp.Close
	}
	sni, ok := _req.(string)
	if !ok {
		return tcp.Close
	}
	for _, h := range s.AllowedSNI {
		if sni == h {
			return tcp.Continue
		}
	}
	return s.ipf.Handle(conn)
}

type HostAndipFilter struct {
	AllowedHosts []string
	ipf          tcp.ServiceHandler
}

func (s *HostAndipFilter) Handle(conn *tcp.Conn) tcp.SerRet {
	_req, ok := conn.Load(tcp.KeyHTTPRequest)
	if !ok {
		return tcp.Close
	}

	req, ok := _req.(*stdhttp.Request)

	if !ok {
		return tcp.Close
	}

	for _, h := range s.AllowedHosts {
		if req.Host == h {
			return tcp.Continue
		}
	}
	return s.ipf.Handle(conn)
}

var builtinTcpServices = map[string]tcp.ServiceHandler{
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
}

func LoadCfgV2(cfgs []byte) error {
	var cfg TopLevelConfig
	err := yaml.Unmarshal(cfgs, &cfg)
	if err != nil {
		return err
	}
	aaa := Assert{
		Type: "map",
		Subnodes: AssertMap{
			"hosts": {
				Type:     "list",
				Required: true,
				Subnodes: AssertMap{
					"_": {
						Type: "map",
						Subnodes: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
							},
							"hosts": {
								Type:     "list",
								Required: true,
								Subnodes: AssertMap{
									"_": {Type: "string"},
								},
							},
							"backend": {
								Type:     "string",
								Required: true,
							},
							"MaxConnsPerHost": {
								Type: "int",
							},
							"TlsSkipVerify": {
								Type: "bool",
							},
						},
					},
				},
			},
		},
	}
	nodes, err := ParseFromAny(cfg.Services[0].ArgsRaw)
	if err != nil {
		return err
	}
	err = nodes.Assert(aaa)

	if err != nil {
		return err
	}
	log.Println(nodes)

	return nil
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
		log.Loggers = []log.Logger{}
	}

	if cfg.Logger.File != "" {
		f, _ := os.OpenFile(cfg.Logger.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		log.Loggers = append(log.Loggers, f)
		log.Println("sys", "File Logger Registered", cfg.Logger.File)
	}

	if cfg.Logger.UDP.Address != "" {
		log.Loggers = append(log.Loggers, NewUdpLogger(cfg.Logger.UDP.Address))
		log.Println("sys", "UDP Logger Registered", cfg.Logger.UDP.Address)
	}

	if cfg.Logger.EnableSSE {
		log.Loggers = append(log.Loggers, Sselogger)
		log.Println("sys", "SSE Logger Registered")
	}

	var fileBackend = authbackends.NewFileBackend()
	pba.AddBackends([]auth.PolicyBackend{fileBackend})
	log.Println("sys", "auth", "use file backend as [0]")
	for _, u := range cfg.Auth.Users {
		log.Println("sys", "auth", "Found User", u.Username)
		var pks []gossh.PublicKey = nil
		if u.SSHAuthorizedKeys != "" {
			for _, k := range strings.Split(u.SSHAuthorizedKeys, "\n") {
				if k == "" {
					continue
				}
				pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(k))
				if err != nil {
					log.Println("sys", "auth", "Failed to parse authorized key for user", u.Username, err)
					os.Exit(-1)
				} else {
					ak := gossh.MarshalAuthorizedKey(pk)
					log.Println("sys", "auth", "Found authorized key for user", u.Username, string(ak[:len(ak)-1]))
				}
				pks = append(pks, pk)
			}
		}

		fileBackend.SetUser(u.Username, u.PasswordHash, u.AllowForwardProxy, pks, u.SSHAllowPassword)
	}
	if cfg.Auth.LDAP.Url != "" {
		ldapBackend := authbackends.NewLDAPBackend(cfg.Auth.LDAP.Url, cfg.Auth.LDAP.SearchBase, cfg.Auth.LDAP.BindDN, cfg.Auth.LDAP.BindPW)
		pba.AddBackends([]auth.PolicyBackend{ldapBackend})
		log.Println("sys", "auth", "use ldap backend as [1]")
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

	log.Println("sys", "ipfilter", "Found", len(cfg.IPFilter.AllowedCIDR), "CIDR")
	builtinTcpServices["ipfilter"] = tcp.NewIPFilter(cfg.IPFilter.AllowedCIDR)
	for _, c := range cfg.IPFilter.AllowedCIDR {
		log.Println("sys", "ipfilter", "Allowed", c)
	}

	builtinTcpServices["sif"] = &SniAndipFilter{
		AllowedSNI: cfg.IPFilter.AllowedSNI,
		ipf:        builtinTcpServices["ipfilter"],
	}

	builtinTcpServices["hif"] = &HostAndipFilter{
		AllowedHosts: cfg.IPFilter.AllowedSNI,
		ipf:          builtinTcpServices["ipfilter"],
	}

	for _, bind := range cfg.HTTP.Midware.Binds {
		if bind.Name == "" {
			bind.Name = bind.Id
		}
		log.Println("sys", "http", "Binding", bind.Id, "with name", bind.Name)
		var hosts []*regexp2.Regexp
		service, ok := builtinHttpServices[bind.Id]
		if !ok {
			return errors.New("service " + bind.Id + " not found")
		}
		if len(bind.Hosts) == 0 {
			hosts = service.Hosts()
		} else {
			hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(bind.Hosts))
		}

		if err != nil {
			break
		}
		HttpMidware.AddServices(&http.ServiceStruct{
			Id:             bind.Name,
			Hosts:          hosts,
			ServiceHandler: service.HandleHTTP,
		})

		switch bind.Id {
		case "Proxier":
			HttpMidware.AddCgis(HttpProxier)
		case "Auth":
			HttpMidware.AddCgis(pba)
		}
	}
	for _, f := range cfg.HTTP.Forward {
		log.Println("sys", "http", "Forward", f)
		v, ok := builtinForwardProxiers[f]
		if !ok {
			log.Println("sys", "http", "Forward", f, "not found")
			os.Exit(-1)
		} else {
			HttpMidware.AddForwardProxiers(v)
		}
	}

	if err != nil {
		log.Println("sys", "http", err)
		os.Exit(-1)
	}

	for _, host := range cfg.HTTP.Proxier.Hosts {
		log.Println("sys", "httpproxy", host.Name, host.Hosts)
		if err := HttpProxier.Insert(HttpProxier.Len(), host.Name, host.Hosts, host.Backend, host.MaxConnsPerHost, host.TlsSkipVerify); err != nil {
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

	if len(cfg.ACME.Hosts) > 0 {
		acmec := AcmeWebRoot{
			AllowedHosts: cfg.ACME.Hosts,
			WWWRoot:      cfg.ACME.WWWRoot,
		}
		builtinTcpServices["acme"] = &acmec
	}

	var prik []gossh.Signer
	if len(cfg.SSH.PrivateKeys) > 0 {
		for _, key := range cfg.SSH.PrivateKeys {
			s, err := gossh.ParsePrivateKey([]byte(key))
			if err != nil {
				log.Println("sys", "ssh", err)
				os.Exit(-1)
			}
			ak := gossh.MarshalAuthorizedKey(s.PublicKey())
			log.Println("sys", "ssh", "Found private key with authorized key", string(ak[:len(ak)-1]), "fingerprint", gossh.FingerprintSHA256(s.PublicKey()))
			prik = append(prik, s)
		}

		var quotes = []string{}
		for _, q := range cfg.SSH.Quotes {
			quotes = append(quotes, strings.TrimSpace(q))
		}

		var sshs = ssh.NewSSHController(prik, cfg.SSH.Banner, quotes, nil, pba.CheckSSHKey)
		hm := map[string]ssh.Host{}
		for i, u := range cfg.SSH.Hosts {
			u.Host = strings.ToLower(u.Host)
			log.Println("sys", "ssh", "Host", u.Host, u.Hostname, u.Pubkey)
			var pubkey gossh.PublicKey = nil
			if u.Pubkey != "" {
				pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(u.Pubkey))
				if err != nil {
					log.Println("sys", "ssh", "Failed to parse authorized key for host", u.Host, err)
					os.Exit(-1)
				}
				pubkey = pk
			}
			hm[u.Host] = ssh.Host{
				Name:   u.Host,
				Addr:   u.Hostname,
				Pubkey: pubkey,
			}
			if i == 0 {
				log.Println("sys", "ssh", "Default Host", u.Host)
				hm[""] = hm[u.Host]
			}
		}

		sshs.AddHandler(ssh.NewSSHProxier(hm, prik), utils.MustCompileRegexp([]string{"^.*$"}))
		builtinTcpServices["ssh"] = sshs
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
		// if err = TcpController.Bind(protocol, bindings); err != nil {
		// 	break
		// }

		var _bindings []tcp.ServiceBinding
		for _, g := range bindings {
			s, ok := builtinTcpServices[g]
			if !ok {
				log.Println("service " + g + " not found")
				os.Exit(-1)
			}
			_bindings = append(_bindings, tcp.ServiceBinding{
				Name:           g,
				ServiceHandler: s,
			})
		}
		TcpController.Bind(protocol, _bindings...)
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
	log.Println("sys", "dns", "domain is", strconv.Quote(cfg.DNS.Domain))
	Dns.SetDomain(cfg.DNS.Domain)
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
		log.Println("sys", "dns", "Record", r.Name, r.Type, r.Value)
		Dns.AddRecord(regexp2.MustCompile(dns.Dnsname2Regexp(r.Name), 0), dns.DnsStringTypeToInt(r.Type), r.Value, uint32(r.Ttl))
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
